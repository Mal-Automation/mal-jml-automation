"""1Password vault access via the SCIM Bridge + Events API.

Why SCIM and not Connect? 1Password Connect only reads/writes *items* inside
vaults; it cannot manage people. Membership is managed by the 1Password SCIM
Bridge (SCIM 2.0). Vault permissions are granted to *groups* once by an admin
(e.g. group ``Engineering`` -> vaults ``Eng-Shared``, ``Eng-Prod``), so
group membership is how vault access is granted and removed.

Real endpoints:

* ``GET   /scim/v2/Users?filter=userName eq "x"``   - lookup
* ``POST  /scim/v2/Users``                           - provision (sends invite)
* ``GET   /scim/v2/Groups?filter=displayName eq "x"``- find vault group
* ``PATCH /scim/v2/Groups/{id}``  op=add members     - grant vault access
* ``PATCH /scim/v2/Groups/{id}``  op=remove members  - revoke vault access
* ``PATCH /scim/v2/Users/{id}``   active=false       - suspend (kills any
  remaining direct vault grants and active sessions)
* ``POST  {events}/api/v1/auditevents``              - verify the audit trail
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

import requests

from jml.config import OnePasswordConfig
from jml.fixtures import load_fixture
from jml.http import build_session
from jml.models import Employee

log = logging.getLogger(__name__)

SCIM_USER = "urn:ietf:params:scim:schemas:core:2.0:User"
SCIM_PATCH = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
SCIM_CT = "application/scim+json"


class OnePasswordError(RuntimeError):
    pass


class OnePasswordClient:
    def __init__(
        self,
        cfg: OnePasswordConfig,
        live: bool,
        session: requests.Session | None = None,
        timeout: float = 15.0,
    ) -> None:
        self.cfg = cfg
        self.live = live
        self.timeout = timeout
        self.session = session or build_session()

    # ------------------------------------------------------------------ helpers
    def _scim(self, method: str, path: str, **kwargs) -> dict:
        headers = {
            "Authorization": f"Bearer {self.cfg.scim_token}",
            "Content-Type": SCIM_CT,
            "Accept": SCIM_CT,
        }
        resp = self.session.request(
            method,
            f"{self.cfg.scim_url}/scim/v2{path}",
            headers=headers,
            timeout=self.timeout,
            **kwargs,
        )
        if resp.status_code >= 400:
            raise OnePasswordError(f"{method} {path} -> HTTP {resp.status_code}: {resp.text[:200]}")
        return resp.json() if resp.content else {}

    @staticmethod
    def _first(listing: dict) -> dict | None:
        res = listing.get("Resources") or []
        return res[0] if res else None

    # ------------------------------------------------------------------ reads
    def find_user(self, email: str) -> dict | None:
        if not self.live:
            return load_fixture("op_user", email=email, first_name="", last_name="")
        return self._first(self._scim("GET", "/Users", params={"filter": f'userName eq "{email}"'}))

    def find_group(self, name: str) -> dict | None:
        if not self.live:
            return load_fixture("op_group", group_name=name)
        return self._first(
            self._scim("GET", "/Groups", params={"filter": f'displayName eq "{name}"'})
        )

    # ------------------------------------------------------------------ joiner
    def provision_user(self, emp: Employee) -> dict:
        if not self.live:
            return load_fixture(
                "op_user",
                email=emp.email,
                first_name=emp.first_name,
                last_name=emp.last_name,
            )
        existing = self.find_user(emp.email)
        if existing:
            return existing
        body = {
            "schemas": [SCIM_USER],
            "userName": emp.email,
            "displayName": emp.full_name,
            "name": {"givenName": emp.first_name, "familyName": emp.last_name},
            "emails": [{"value": emp.email, "primary": True}],
            "active": True,
        }
        return self._scim("POST", "/Users", json=body)

    def add_to_vault_group(self, user_id: str, group_name: str) -> dict:
        group = self.find_group(group_name)
        if not group:
            raise OnePasswordError(f"Vault group {group_name!r} does not exist in 1Password")
        if self.live:
            self._scim(
                "PATCH",
                f"/Groups/{group['id']}",
                json={
                    "schemas": [SCIM_PATCH],
                    "Operations": [{"op": "add", "path": "members", "value": [{"value": user_id}]}],
                },
            )
        return {"groupId": group["id"], "groupName": group["displayName"]}

    # ------------------------------------------------------------------ leaver
    def remove_from_all_vault_groups(self, email: str) -> list[str]:
        """Remove the user from every group (=> every shared vault), then suspend."""
        user = self.find_user(email)
        if not user:
            raise OnePasswordError(f"User {email} not found in 1Password")
        uid = user["id"]
        removed, errors = [], []
        for g in user.get("groups", []):
            name = g.get("display", g["value"])
            if self.live:
                try:
                    self._scim(
                        "PATCH",
                        f"/Groups/{g['value']}",
                        json={
                            "schemas": [SCIM_PATCH],
                            "Operations": [{"op": "remove", "path": f'members[value eq "{uid}"]'}],
                        },
                    )
                except OnePasswordError as exc:
                    errors.append(f"{name}: {exc}")
                    continue
            removed.append(name)
        if self.live:
            self._scim(
                "PATCH",
                f"/Users/{uid}",
                json={
                    "schemas": [SCIM_PATCH],
                    "Operations": [{"op": "replace", "path": "active", "value": False}],
                },
            )
        if errors:
            raise OnePasswordError(f"Removed {removed}; failed: {errors}")
        return removed

    def recent_audit_events(self, email: str, hours: int = 1) -> list[dict]:
        """Pull recent audit events touching ``email`` from the Events API."""
        if not self.live or not self.cfg.events_token:
            events = load_fixture("op_audit_events", email=email)["items"]
        else:
            start = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()
            resp = self.session.post(
                f"{self.cfg.events_url}/api/v1/auditevents",
                headers={"Authorization": f"Bearer {self.cfg.events_token}"},
                json={"limit": 100, "start_time": start},
                timeout=self.timeout,
            )
            if resp.status_code >= 400:
                raise OnePasswordError(f"Events API HTTP {resp.status_code}")
            events = resp.json().get("items", [])
        return [
            e
            for e in events
            if email in str(e.get("aux_info", ""))
            or email in str(e.get("object_uuid"))
            or email == (e.get("actor_details") or {}).get("email")
            or email == (e.get("object_details") or {}).get("email")
        ]
