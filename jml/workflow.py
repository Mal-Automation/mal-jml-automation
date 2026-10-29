"""Orchestrates the Joiner and Leaver workflows across all integrations.

Design rules:

* **Never stop early on a leaver.** If Okta fails we still revoke Google tokens
  and 1Password access - partial revocation beats no revocation. Every
  step's outcome is recorded and failures are surfaced in the alert.
* **Dependent steps are skipped, not failed**, when their prerequisite failed
  (e.g. no Okta group assignment if the Okta user could not be created).
* **Every run writes a JSON audit record** to ``reports/``.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Callable
from pathlib import Path
from typing import Any

from jml.clients.google_workspace import GoogleWorkspaceClient
from jml.clients.mdm import JamfClient
from jml.clients.okta import OktaClient
from jml.clients.onepassword import OnePasswordClient
from jml.config import Settings
from jml.models import ActionResult, Employee, Status, WorkflowReport
from jml.notify import Notifier

log = logging.getLogger(__name__)


class JMLWorkflow:
    def __init__(
        self,
        settings: Settings,
        okta: OktaClient | None = None,
        gws: GoogleWorkspaceClient | None = None,
        onepassword: OnePasswordClient | None = None,
        mdm: JamfClient | None = None,
        notifier: Notifier | None = None,
        report_dir: str | Path = "reports",
    ) -> None:
        s = settings
        t = s.http_timeout
        self.okta = okta or OktaClient(s.okta, s.is_live(s.okta.configured, "Okta"), timeout=t)
        self.gws = gws or GoogleWorkspaceClient(
            s.google, s.is_live(s.google.configured, "Google Workspace")
        )
        self.onepassword = onepassword or OnePasswordClient(
            s.onepassword, s.is_live(s.onepassword.configured, "1Password"), timeout=t
        )
        self.mdm = mdm or JamfClient(s.jamf, s.is_live(s.jamf.configured, "Jamf"), timeout=t)
        self.notifier = notifier or Notifier(s.notify)
        self.report_dir = Path(report_dir)

    # ------------------------------------------------------------------ engine
    @staticmethod
    def _step(
        report: WorkflowReport,
        system: str,
        action: str,
        live: bool,
        fn: Callable[[], Any],
        describe: Callable[[Any], str] = lambda r: "ok",
    ) -> tuple[ActionResult, Any]:
        log.info("-> %s: %s%s", system, action, "" if live else " (mock)")
        try:
            value = fn()
            res = ActionResult(system, action, Status.SUCCESS, describe(value), not live)
            if isinstance(value, dict):
                res.data = value
        except Exception as exc:  # noqa: BLE001 - we record every failure
            log.error("x  %s: %s failed: %s", system, action, exc)
            value = None
            res = ActionResult(system, action, Status.FAILED, str(exc), not live)
        return report.add(res), value

    @staticmethod
    def _skip(report: WorkflowReport, system: str, action: str, why: str) -> None:
        report.add(ActionResult(system, action, Status.SKIPPED, why))

    def _persist(self, report: WorkflowReport) -> Path:
        self.report_dir.mkdir(parents=True, exist_ok=True)
        safe = report.user.replace("@", "_at_")
        ts = (report.finished_at or report.started_at).replace(":", "").replace("+", "_")
        path = self.report_dir / f"{report.event}-{safe}-{ts}.json"
        path.write_text(json.dumps(report.to_dict(), indent=2, default=str))
        return path

    # ------------------------------------------------------------------ joiner
    def onboard(self, emp: Employee, notify: bool = True) -> WorkflowReport:
        report = WorkflowReport(event="joiner", user=emp.email)

        # 1. Okta
        res, okta_user = self._step(
            report,
            "Okta",
            "create & activate user",
            self.okta.live,
            lambda: self.okta.create_user(emp),
            lambda u: f"id={u['id']} status={u.get('status')}",
        )
        if res.ok and okta_user:
            self._step(
                report,
                "Okta",
                f"assign group '{emp.okta_group}'",
                self.okta.live,
                lambda: self.okta.add_user_to_group(okta_user["id"], emp.okta_group),
                lambda g: f"groupId={g['groupId']}",
            )
        else:
            self._skip(report, "Okta", f"assign group '{emp.okta_group}'", "user creation failed")

        # 2. Google Workspace
        self._step(
            report,
            "Google Workspace",
            "create user",
            self.gws.live,
            lambda: self.gws.create_user(emp),
            lambda u: f"id={u.get('id')} (password reset forced at first login)",
        )

        # 3. 1Password
        res, op_user = self._step(
            report,
            "1Password",
            "provision user (invite)",
            self.onepassword.live,
            lambda: self.onepassword.provision_user(emp),
            lambda u: f"id={u['id']}",
        )
        if res.ok and op_user:
            self._step(
                report,
                "1Password",
                f"add to vault group '{emp.vault_group}'",
                self.onepassword.live,
                lambda: self.onepassword.add_to_vault_group(op_user["id"], emp.vault_group),
                lambda g: f"groupId={g['groupId']}",
            )
        else:
            self._skip(
                report,
                "1Password",
                f"add to vault group '{emp.vault_group}'",
                "user provisioning failed",
            )

        # 4. MDM
        self._step(
            report,
            "Jamf (MDM)",
            "send enrollment invitation",
            self.mdm.live,
            lambda: self.mdm.send_enrollment_invitation(emp),
            lambda r: f"invitation id={r['response'].get('id')} sent to {emp.email}",
        )

        report.finish()
        log.info("Audit record written to %s", self._persist(report))
        if notify:
            self.notifier.notify(report)
        return report

    # ------------------------------------------------------------------ leaver
    def _gws_lockout(self, email: str) -> dict:
        self.gws.sign_out(email)
        self.gws.suspend_user(email)
        return {"signed_out": True, "suspended": True}

    def offboard(self, email: str, okta_mode: str = "deactivate") -> WorkflowReport:
        email = email.strip().lower()
        report = WorkflowReport(event="leaver", user=email)

        # 1. Identity first: kill the IdP session so no new SSO logins happen.
        self._step(
            report,
            "Okta",
            f"clear sessions + {okta_mode} user",
            self.okta.live,
            lambda: self.okta.offboard(email, okta_mode),
            lambda r: f"id={r['id']} -> {r['status']}",
        )

        # 2. Google: revoke third-party OAuth grants, sign out, suspend.
        self._step(
            report,
            "Google Workspace",
            "revoke all OAuth tokens",
            self.gws.live,
            lambda: {"revoked": self.gws.revoke_oauth_tokens(email)},
            lambda r: f"{len(r['revoked'])} revoked: "
            + (", ".join(t.get("displayText") or t["clientId"] for t in r["revoked"]) or "none"),
        )
        self._step(
            report,
            "Google Workspace",
            "sign out all sessions & suspend",
            self.gws.live,
            lambda: self._gws_lockout(email),
            lambda r: "signed out, suspended",
        )

        # 3. 1Password: strip every vault group, then suspend.
        self._step(
            report,
            "1Password",
            "remove from all shared vaults & suspend",
            self.onepassword.live,
            lambda: {"removed_groups": self.onepassword.remove_from_all_vault_groups(email)},
            lambda r: "removed from: " + (", ".join(r["removed_groups"]) or "no groups"),
        )

        # 4. Verify via 1Password Events API (informational, never fatal).
        try:
            events = self.onepassword.recent_audit_events(email)
            report.add(
                ActionResult(
                    "1Password",
                    "verify audit trail (Events API)",
                    Status.SUCCESS,
                    f"{len(events)} matching audit event(s)",
                    not (self.onepassword.live and self.onepassword.cfg.events_token),
                )
            )
        except Exception as exc:  # noqa: BLE001
            self._skip(report, "1Password", "verify audit trail (Events API)", str(exc))

        report.finish()
        log.info("Audit record written to %s", self._persist(report))
        channels = self.notifier.notify(report)
        log.info("Offboarding alert sent via: %s", ", ".join(channels))
        return report
