from datetime import datetime, timezone

import requests
import responses

from jml.clients.mdm import JamfClient, build_invitation_xml
from jml.config import JamfConfig
from jml.models import Employee

JAMF = "https://mal.jamfcloud.com"


def test_invitation_xml_is_realistic_and_escaped():
    emp = Employee(first_name="Tom", last_name="O'Neil & Co", email="tom@mal.example")
    xml = build_invitation_xml(emp, 14, now=datetime(2026, 1, 1, tzinfo=timezone.utc))
    assert "<invitation_type>EMAIL</invitation_type>" in xml
    assert "<email_address>tom@mal.example</email_address>" in xml
    assert "2026-01-15T00:00:00.000+0000" in xml
    assert "O'Neil &amp; Co" in xml


def test_mock_invitation_logs_and_returns_fixture(employee, caplog):
    client = JamfClient(JamfConfig(None, None, None, 14), live=False)
    with caplog.at_level("INFO"):
        out = client.send_enrollment_invitation(employee)
    assert out["response"]["status"] == 201
    assert out["response"]["sent_to"] == employee.email
    assert "computerinvitations" in caplog.text


@responses.activate
def test_live_invitation_flow(employee):
    responses.post(f"{JAMF}/api/v1/auth/token", json={"token": "bearer-x", "expires": "z"})
    responses.post(
        f"{JAMF}/JSSResource/computerinvitations/id/0",
        status=201,
        body="<computer_invitation><id>77</id></computer_invitation>",
    )
    responses.post(f"{JAMF}/api/v1/auth/invalidate-token", status=204)
    client = JamfClient(JamfConfig(JAMF, "api", "pw", 14), live=True, session=requests.Session())
    out = client.send_enrollment_invitation(employee)
    assert out["response"] == {"status": 201, "id": "77"}
    assert responses.calls[1].request.headers["Authorization"] == "Bearer bearer-x"
    assert len(responses.calls) == 3  # token always invalidated
