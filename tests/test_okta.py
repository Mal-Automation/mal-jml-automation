import json

import pytest
import requests
import responses

from jml.clients.okta import OktaClient, OktaError
from jml.config import OktaConfig

BASE = "https://dev-123.okta.com"
CFG = OktaConfig(org_url=BASE, api_token="secret-token")


@pytest.fixture
def okta():
    return OktaClient(CFG, live=True, session=requests.Session())


@responses.activate
def test_create_user_posts_profile_and_activates(okta, employee):
    responses.get(f"{BASE}/api/v1/users/{employee.email}", status=404, json={})
    responses.post(f"{BASE}/api/v1/users", json={"id": "00u1", "status": "ACTIVE"})
    user = okta.create_user(employee)
    assert user["id"] == "00u1"
    call = responses.calls[1].request
    assert "activate=true" in call.url
    assert call.headers["Authorization"] == "SSWS secret-token"
    body = json.loads(call.body)
    assert body["profile"]["login"] == employee.email
    assert body["profile"]["firstName"] == "Ada"


@responses.activate
def test_create_user_is_idempotent(okta, employee):
    responses.get(f"{BASE}/api/v1/users/{employee.email}", json={"id": "00uX"})
    assert okta.create_user(employee)["id"] == "00uX"
    assert len(responses.calls) == 1  # no POST


@responses.activate
def test_add_user_to_existing_group(okta):
    responses.get(
        f"{BASE}/api/v1/groups",
        json=[{"id": "00gE", "profile": {"name": "engineering"}}],
    )
    responses.put(f"{BASE}/api/v1/groups/00gE/users/00u1", status=204)
    res = okta.add_user_to_group("00u1", "engineering")
    assert res == {"groupId": "00gE", "groupName": "engineering"}


@responses.activate
def test_add_user_creates_missing_group(okta):
    responses.get(f"{BASE}/api/v1/groups", json=[])
    responses.post(f"{BASE}/api/v1/groups", json={"id": "00gN", "profile": {"name": "eng"}})
    responses.put(f"{BASE}/api/v1/groups/00gN/users/00u1", status=204)
    assert okta.add_user_to_group("00u1", "eng")["groupId"] == "00gN"


@responses.activate
def test_offboard_clears_sessions_then_deactivates(okta):
    responses.get(f"{BASE}/api/v1/users/bob@mal.example", json={"id": "00u9", "status": "ACTIVE"})
    responses.delete(f"{BASE}/api/v1/users/00u9/sessions", status=204)
    responses.post(f"{BASE}/api/v1/users/00u9/lifecycle/deactivate", status=200, json={})
    res = okta.offboard("bob@mal.example")
    assert res["status"] == "DEPROVISIONED"
    assert "oauthTokens=true" in responses.calls[1].request.url
    assert responses.calls[2].request.url.endswith("sendEmail=false")


@responses.activate
def test_offboard_suspend_mode(okta):
    responses.get(f"{BASE}/api/v1/users/bob@mal.example", json={"id": "00u9", "status": "ACTIVE"})
    responses.delete(f"{BASE}/api/v1/users/00u9/sessions", status=204)
    responses.post(f"{BASE}/api/v1/users/00u9/lifecycle/suspend", status=200, json={})
    assert okta.offboard("bob@mal.example", mode="suspend")["status"] == "SUSPENDED"


@responses.activate
def test_offboard_unknown_user_raises(okta):
    responses.get(f"{BASE}/api/v1/users/ghost@mal.example", status=404, json={})
    with pytest.raises(OktaError, match="not found"):
        okta.offboard("ghost@mal.example")


@responses.activate
def test_api_error_surfaces_error_summary(okta, employee):
    responses.get(f"{BASE}/api/v1/users/{employee.email}", status=404, json={})
    responses.post(
        f"{BASE}/api/v1/users",
        status=400,
        json={
            "errorSummary": "Api validation failed: login",
            "errorCauses": [{"errorSummary": "login: already exists"}],
        },
    )
    with pytest.raises(OktaError, match="already exists"):
        okta.create_user(employee)


def test_mock_mode_makes_no_http_calls(employee):
    client = OktaClient(OktaConfig(None, None), live=False)
    with responses.RequestsMock() as rsps:  # any HTTP call would raise
        user = client.create_user(employee)
        assert user["profile"]["email"] == employee.email
        assert client.offboard(employee.email)["status"] == "DEPROVISIONED"
        assert len(rsps.calls) == 0
