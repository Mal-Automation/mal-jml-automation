"""Completion alerts: Slack incoming webhook, SMTP e-mail, or console fallback."""

from __future__ import annotations

import json
import logging
import smtplib
from email.message import EmailMessage

import requests

from jml.config import NotifyConfig
from jml.models import Status, WorkflowReport

log = logging.getLogger(__name__)

ICON = {
    Status.SUCCESS: ":white_check_mark:",
    Status.FAILED: ":x:",
    Status.SKIPPED: ":fast_forward:",
}


def format_text(report: WorkflowReport) -> str:
    """Plain-text summary (used for e-mail and console)."""
    head = "COMPLETED" if report.succeeded else f"COMPLETED WITH {len(report.failures)} FAILURE(S)"
    lines = [
        f"JML {report.event.upper()} {head}",
        f"User:      {report.user}",
        f"Started:   {report.started_at}",
        f"Finished:  {report.finished_at}",
        "",
        "Actions taken:",
    ]
    for r in report.results:
        tag = " [mock]" if r.mocked else ""
        lines.append(f"  [{r.status.value.upper():7}] {r.system}: {r.action}{tag} - {r.detail}")
    if report.failures:
        lines += ["", "Failures requiring manual follow-up:"]
        lines += [f"  - {r.system}: {r.action} -> {r.detail}" for r in report.failures]
    return "\n".join(lines)


def build_slack_payload(report: WorkflowReport) -> dict:
    """Slack Block Kit message summarising the run."""
    ok = report.succeeded
    title = (
        f"{':large_green_circle:' if ok else ':red_circle:'} "
        f"{report.event.capitalize()} {'completed' if ok else 'completed with failures'}"
    )
    action_lines = "\n".join(
        f"{ICON[r.status]} *{r.system}* - {r.action}{' _(mock)_' if r.mocked else ''}"
        for r in report.results
    )
    blocks: list[dict] = [
        {"type": "header", "text": {"type": "plain_text", "text": title[:150]}},
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*User:*\n{report.user}"},
                {"type": "mrkdwn", "text": f"*Timestamp (UTC):*\n{report.finished_at}"},
                {"type": "mrkdwn", "text": f"*Actions:*\n{len(report.results)}"},
                {"type": "mrkdwn", "text": f"*Failures:*\n{len(report.failures)}"},
            ],
        },
        {"type": "section", "text": {"type": "mrkdwn", "text": action_lines[:2900] or "-"}},
    ]
    if report.failures:
        fail_text = "\n".join(f"- *{r.system}*: {r.detail}" for r in report.failures)
        blocks.append(
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*:warning: Needs follow-up*\n{fail_text}"[:2900],
                },
            }
        )
    blocks.append(
        {
            "type": "context",
            "elements": [
                {"type": "mrkdwn", "text": f"jml-automation | started {report.started_at}"}
            ],
        }
    )
    return {"text": f"{title} for {report.user}", "blocks": blocks}


class Notifier:
    def __init__(
        self, cfg: NotifyConfig, session: requests.Session | None = None, timeout: float = 10.0
    ):
        self.cfg = cfg
        self.session = session or requests.Session()
        self.timeout = timeout

    def send_slack(self, report: WorkflowReport) -> None:
        resp = self.session.post(
            self.cfg.slack_webhook_url,
            data=json.dumps(build_slack_payload(report)),
            headers={"Content-Type": "application/json"},
            timeout=self.timeout,
        )
        if resp.status_code != 200:
            raise RuntimeError(f"Slack webhook HTTP {resp.status_code}: {resp.text[:100]}")

    def send_email(self, report: WorkflowReport) -> None:
        msg = EmailMessage()
        status = "OK" if report.succeeded else "FAILURES"
        msg["Subject"] = f"[JML] {report.event} {status}: {report.user}"
        msg["From"] = self.cfg.email_from
        msg["To"] = self.cfg.email_to
        msg.set_content(format_text(report))
        with smtplib.SMTP(self.cfg.smtp_host, self.cfg.smtp_port, timeout=self.timeout) as smtp:
            smtp.starttls()
            if self.cfg.smtp_username:
                smtp.login(self.cfg.smtp_username, self.cfg.smtp_password or "")
            smtp.send_message(msg)

    def notify(self, report: WorkflowReport) -> list[str]:
        """Send to every configured channel. Returns channels that succeeded.

        Alert failures are logged but never raised: losing the alert must not
        mask the fact that the access changes themselves already happened.
        """
        sent: list[str] = []
        if self.cfg.slack_configured:
            try:
                self.send_slack(report)
                sent.append("slack")
            except Exception as exc:  # noqa: BLE001
                log.error("Slack alert failed: %s", exc)
        if self.cfg.email_configured:
            try:
                self.send_email(report)
                sent.append("email")
            except Exception as exc:  # noqa: BLE001
                log.error("E-mail alert failed: %s", exc)
        if not sent:
            print("\n" + format_text(report) + "\n")
            sent.append("console")
        return sent
