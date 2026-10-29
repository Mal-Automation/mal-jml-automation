"""MDM enrollment invitation (Jamf Pro).

Jamf Pro has no self-serve free tier, so this integration is **mocked by
default**: the exact request that would be sent is built, logged, and answered
with a fixture modelled on Jamf Pro's real responses. If ``JAMF_URL``,
``JAMF_USERNAME`` and ``JAMF_PASSWORD`` are set (and ``JML_MODE`` is not
``mock``) the same payload is sent for real:

1. ``POST /api/v1/auth/token``                          (basic auth -> bearer)
2. ``POST /JSSResource/computerinvitations/id/0``       (XML invitation)
3. ``POST /api/v1/auth/invalidate-token``               (clean up)
"""

from __future__ import annotations

import logging
import re
import uuid
from datetime import datetime, timedelta, timezone
from xml.sax.saxutils import escape

import requests

from jml.config import JamfConfig
from jml.fixtures import load_fixture
from jml.models import Employee

log = logging.getLogger(__name__)


class MDMError(RuntimeError):
    pass


def build_invitation_xml(emp: Employee, expiry_days: int, now: datetime | None = None) -> str:
    """Build the Jamf Pro Classic API computer-invitation payload."""
    now = now or datetime.now(timezone.utc)
    expires = now + timedelta(days=expiry_days)
    epoch_ms = int(expires.timestamp() * 1000)
    return (
        "<computer_invitation>"
        "<invitation_type>EMAIL</invitation_type>"
        f"<expiration_date_utc>{expires.strftime('%Y-%m-%dT%H:%M:%S.000+0000')}"
        "</expiration_date_utc>"
        f"<expiration_date_epoch>{epoch_ms}</expiration_date_epoch>"
        "<multiple_users_allowed>false</multiple_users_allowed>"
        "<create_account_if_does_not_exist>false</create_account_if_does_not_exist>"
        "<keep_existing_site_membership>false</keep_existing_site_membership>"
        f"<invited_user_uuid>{uuid.uuid5(uuid.NAMESPACE_DNS, emp.email)}</invited_user_uuid>"
        "<enroll_into_site><id>-1</id><name>None</name></enroll_into_site>"
        f"<email_address>{escape(emp.email)}</email_address>"
        f"<full_name>{escape(emp.full_name)}</full_name>"
        f"<department>{escape(emp.department)}</department>"
        "</computer_invitation>"
    )


class JamfClient:
    def __init__(
        self,
        cfg: JamfConfig,
        live: bool,
        session: requests.Session | None = None,
        timeout: float = 15.0,
    ) -> None:
        self.cfg = cfg
        self.live = live
        self.timeout = timeout
        self.session = session or requests.Session()

    def _token(self) -> str:
        resp = self.session.post(
            f"{self.cfg.url}/api/v1/auth/token",
            auth=(self.cfg.username, self.cfg.password),
            timeout=self.timeout,
        )
        if resp.status_code != 200:
            raise MDMError(f"Jamf auth failed: HTTP {resp.status_code}")
        return resp.json()["token"]

    def send_enrollment_invitation(self, emp: Employee) -> dict:
        """Create an e-mailed enrollment invitation. Returns request + response."""
        payload = build_invitation_xml(emp, self.cfg.invitation_expiry_days)
        endpoint = "/JSSResource/computerinvitations/id/0"
        log.info("MDM request POST %s payload=%s", endpoint, payload)

        if not self.live:
            response = load_fixture(
                "jamf_invitation",
                email=emp.email,
                jamf_url=self.cfg.url or "https://mal.jamfcloud.com",
            )
            log.info("MDM mocked response: %s", response)
            return {"endpoint": endpoint, "request": payload, "response": response}

        token = self._token()
        try:
            resp = self.session.post(
                f"{self.cfg.url}{endpoint}",
                data=payload.encode(),
                headers={
                    "Authorization": f"Bearer {token}",
                    "Content-Type": "application/xml",
                    "Accept": "application/xml",
                },
                timeout=self.timeout,
            )
            if resp.status_code not in (200, 201):
                raise MDMError(f"Jamf invitation HTTP {resp.status_code}: {resp.text[:200]}")
            match = re.search(r"<id>(\d+)</id>", resp.text)
            response = {"status": resp.status_code, "id": match.group(1) if match else None}
        finally:
            self.session.post(
                f"{self.cfg.url}/api/v1/auth/invalidate-token",
                headers={"Authorization": f"Bearer {token}"},
                timeout=self.timeout,
            )
        log.info("MDM response: %s", response)
        return {"endpoint": endpoint, "request": payload, "response": response}
