"""Google Workspace provisioning via the Admin SDK Directory API.

Real calls (service account + domain-wide delegation, works on a GWS trial):

* ``users.insert``      - create the account (random temp password, forced reset)
* ``users.get``         - idempotency check
* ``tokens.list``       - enumerate third-party OAuth grants for the leaver
* ``tokens.delete``     - revoke each grant
* ``users.signOut``     - kill all web and device sessions
* ``users.update``      - suspend the account (``suspended: true``)

Required OAuth scopes on the delegated service account:
``admin.directory.user`` and ``admin.directory.user.security``.
"""

from __future__ import annotations

import logging
import secrets
import string
from typing import Any

from jml.config import GoogleConfig
from jml.fixtures import load_fixture
from jml.models import Employee

log = logging.getLogger(__name__)

SCOPES = [
    "https://www.googleapis.com/auth/admin.directory.user",
    "https://www.googleapis.com/auth/admin.directory.user.security",
]


class GoogleWorkspaceError(RuntimeError):
    pass


def generate_temp_password(length: int = 20) -> str:
    """Cryptographically random password meeting GWS complexity rules."""
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*-_=+"
    while True:
        pw = "".join(secrets.choice(alphabet) for _ in range(length))
        if (
            any(c.islower() for c in pw)
            and any(c.isupper() for c in pw)
            and any(c.isdigit() for c in pw)
            and any(not c.isalnum() for c in pw)
        ):
            return pw


def build_directory_service(cfg: GoogleConfig) -> Any:  # pragma: no cover - network
    """Build an authorised Directory API client using domain-wide delegation."""
    from google.oauth2 import service_account
    from googleapiclient.discovery import build

    creds = service_account.Credentials.from_service_account_file(
        cfg.service_account_file, scopes=SCOPES
    ).with_subject(cfg.admin_subject)
    return build("admin", "directory_v1", credentials=creds, cache_discovery=False)


def _http_status(exc: Exception) -> int | None:
    resp = getattr(exc, "resp", None)
    return getattr(resp, "status", None)


class GoogleWorkspaceClient:
    def __init__(self, cfg: GoogleConfig, live: bool, service: Any = None) -> None:
        self.cfg = cfg
        self.live = live
        self._service = service

    @property
    def service(self) -> Any:
        if self._service is None:
            self._service = build_directory_service(self.cfg)
        return self._service

    # ------------------------------------------------------------------ joiner
    def get_user(self, email: str) -> dict | None:
        try:
            return self.service.users().get(userKey=email).execute()
        except Exception as exc:  # googleapiclient.errors.HttpError
            if _http_status(exc) == 404:
                return None
            raise GoogleWorkspaceError(f"users.get failed: {exc}") from exc

    def create_user(self, emp: Employee, org_unit: str = "/") -> dict:
        """Create the account. The temp password is never returned or logged."""
        if not self.live:
            return load_fixture(
                "gws_user",
                email=emp.email,
                first_name=emp.first_name,
                last_name=emp.last_name,
            )
        existing = self.get_user(emp.email)
        if existing:
            log.info("GWS user %s already exists", emp.email)
            return existing
        body = {
            "primaryEmail": emp.email,
            "name": {"givenName": emp.first_name, "familyName": emp.last_name},
            "password": generate_temp_password(),
            "changePasswordAtNextLogin": True,
            "orgUnitPath": org_unit,
            "organizations": [{"department": emp.department, "title": emp.title, "primary": True}],
        }
        try:
            user = self.service.users().insert(body=body).execute()
        except Exception as exc:
            raise GoogleWorkspaceError(f"users.insert failed: {exc}") from exc
        user.pop("password", None)
        return user

    # ------------------------------------------------------------------ leaver
    def revoke_oauth_tokens(self, email: str) -> list[dict]:
        """Revoke every third-party OAuth grant. Returns the revoked tokens."""
        if not self.live:
            tokens = load_fixture("gws_tokens", email=email)["items"]
            return [{"clientId": t["clientId"], "displayText": t["displayText"]} for t in tokens]
        try:
            items = self.service.tokens().list(userKey=email).execute().get("items", [])
        except Exception as exc:
            raise GoogleWorkspaceError(f"tokens.list failed: {exc}") from exc

        revoked, errors = [], []
        for tok in items:
            try:
                self.service.tokens().delete(userKey=email, clientId=tok["clientId"]).execute()
                revoked.append({"clientId": tok["clientId"], "displayText": tok.get("displayText")})
            except Exception as exc:  # noqa: BLE001 - keep revoking the rest
                errors.append(f"{tok.get('displayText', tok['clientId'])}: {exc}")
        if errors:
            raise GoogleWorkspaceError(
                f"Revoked {len(revoked)}/{len(items)} tokens; failures: {errors}"
            )
        return revoked

    def sign_out(self, email: str) -> None:
        if self.live:
            try:
                self.service.users().signOut(userKey=email).execute()
            except Exception as exc:
                raise GoogleWorkspaceError(f"users.signOut failed: {exc}") from exc

    def suspend_user(self, email: str) -> None:
        if self.live:
            try:
                self.service.users().update(userKey=email, body={"suspended": True}).execute()
            except Exception as exc:
                raise GoogleWorkspaceError(f"users.update failed: {exc}") from exc
