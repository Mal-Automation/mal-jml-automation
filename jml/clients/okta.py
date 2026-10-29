"""Okta user lifecycle via the Okta Management API (v1).

Real endpoints used (works on a free Okta Integrator/Developer org):

* ``GET    /api/v1/users/{login}``                         - lookup
* ``POST   /api/v1/users?activate=true``                    - create + activate
* ``GET    /api/v1/groups?q={name}``                        - find group
* ``POST   /api/v1/groups``                                 - create group if absent
* ``PUT    /api/v1/groups/{groupId}/users/{userId}``        - add to group
* ``DELETE /api/v1/users/{id}/sessions?oauthTokens=true``   - kill sessions/tokens
* ``POST   /api/v1/users/{id}/lifecycle/suspend``           - suspend
* ``POST   /api/v1/users/{id}/lifecycle/deactivate``        - deactivate
"""

from __future__ import annotations

import logging

import requests

from jml.config import OktaConfig
from jml.fixtures import load_fixture
from jml.http import build_session
from jml.models import Employee

log = logging.getLogger(__name__)


class OktaError(RuntimeError):
    pass


class OktaClient:
    def __init__(
        self,
        cfg: OktaConfig,
        live: bool,
        session: requests.Session | None = None,
        timeout: float = 15.0,
    ) -> None:
        self.cfg = cfg
        self.live = live
        self.timeout = timeout
        self.session = session or build_session()
        if live:
            self.session.headers["Authorization"] = f"SSWS {cfg.api_token}"
            self.session.headers["Content-Type"] = "application/json"

    # ------------------------------------------------------------------ helpers
    def _url(self, path: str) -> str:
        return f"{self.cfg.org_url}{path}"

    def _request(self, method: str, path: str, **kwargs) -> requests.Response:
        resp = self.session.request(method, self._url(path), timeout=self.timeout, **kwargs)
        if resp.status_code >= 400:
            try:
                err = resp.json()
                summary = err.get("errorSummary") or err
                causes = [c.get("errorSummary") for c in err.get("errorCauses", [])]
                if causes:
                    summary = f"{summary} ({'; '.join(causes)})"
            except ValueError:
                summary = resp.text[:200]
            raise OktaError(f"{method} {path} -> HTTP {resp.status_code}: {summary}")
        return resp

    # ------------------------------------------------------------------ reads
    def get_user(self, login: str) -> dict | None:
        """Return the Okta user for ``login`` or ``None`` if not found."""
        if not self.live:
            return load_fixture("okta_user", email=login, first_name="", last_name="")
        try:
            return self._request("GET", f"/api/v1/users/{login}").json()
        except OktaError as exc:
            if "HTTP 404" in str(exc):
                return None
            raise

    def find_group(self, name: str) -> dict | None:
        if not self.live:
            return load_fixture("okta_group", group_name=name)
        groups = self._request("GET", "/api/v1/groups", params={"q": name}).json()
        for g in groups:
            if g.get("profile", {}).get("name", "").lower() == name.lower():
                return g
        return None

    # ------------------------------------------------------------------ joiner
    def create_user(self, emp: Employee) -> dict:
        """Create and activate a user. Idempotent: returns existing user if any."""
        if not self.live:
            return load_fixture(
                "okta_user",
                email=emp.email,
                first_name=emp.first_name,
                last_name=emp.last_name,
            )
        existing = self.get_user(emp.email)
        if existing:
            log.info("Okta user %s already exists (%s)", emp.email, existing["id"])
            return existing
        body = {
            "profile": {
                "firstName": emp.first_name,
                "lastName": emp.last_name,
                "email": emp.email,
                "login": emp.email,
                "department": emp.department,
                "title": emp.title,
                "manager": emp.manager_email or None,
            }
        }
        body["profile"] = {k: v for k, v in body["profile"].items() if v}
        return self._request("POST", "/api/v1/users", params={"activate": "true"}, json=body).json()

    def ensure_group(self, name: str) -> dict:
        group = self.find_group(name)
        if group:
            return group
        body = {"profile": {"name": name, "description": f"{name} (managed by JML)"}}
        return self._request("POST", "/api/v1/groups", json=body).json()

    def add_user_to_group(self, user_id: str, group_name: str) -> dict:
        group = self.ensure_group(group_name)
        if self.live:
            self._request("PUT", f"/api/v1/groups/{group['id']}/users/{user_id}")
        return {"groupId": group["id"], "groupName": group["profile"]["name"]}

    # ------------------------------------------------------------------ leaver
    def clear_sessions(self, user_id: str) -> None:
        """Revoke all Okta sessions and Okta-issued OAuth tokens."""
        if self.live:
            self._request(
                "DELETE",
                f"/api/v1/users/{user_id}/sessions",
                params={"oauthTokens": "true"},
            )

    def suspend_user(self, user_id: str) -> None:
        if self.live:
            self._request("POST", f"/api/v1/users/{user_id}/lifecycle/suspend")

    def deactivate_user(self, user_id: str) -> None:
        if self.live:
            self._request(
                "POST",
                f"/api/v1/users/{user_id}/lifecycle/deactivate",
                params={"sendEmail": "false"},
            )

    def offboard(self, login: str, mode: str = "deactivate") -> dict:
        """Kill sessions then suspend or deactivate. Returns final state."""
        if mode not in {"suspend", "deactivate"}:
            raise ValueError("mode must be 'suspend' or 'deactivate'")
        user = self.get_user(login)
        if user is None:
            raise OktaError(f"User {login} not found in Okta")
        uid = user["id"]
        status = user.get("status")
        if status == "DEPROVISIONED":
            return {"id": uid, "status": status, "note": "already deprovisioned"}

        self.clear_sessions(uid)
        if mode == "suspend":
            if status != "SUSPENDED":
                self.suspend_user(uid)
            final = "SUSPENDED"
        else:
            self.deactivate_user(uid)
            final = "DEPROVISIONED"
        return {"id": uid, "previous_status": status, "status": final}
