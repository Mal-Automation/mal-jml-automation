import json

import pytest
import requests
import responses

from jml.clients.onepassword import OnePasswordClient, OnePasswordError
from jml.config import OnePasswordConfig

SCIM = "https://scim.mal.example"
EVENTS = "https://events.1password.com"
CFG = OnePasswordConfig(SCIM, "scim-tok", "events-tok", EVENTS)


@pytest.fixture
def op():
    return OnePasswordClient(CFG, live=True, session=requests.Session())


@responses.activate
def test_provision_user_creates_scim_user(op, employee):
    responses.get(f"{SCIM}/scim/v2/Users", json={"Resources": []})
    responses.post(f"{SCIM}/scim/v2/Users", json={"id": "U1", "userName": employee.email})
    assert op.provision_user(employee)["id"] == "U1"
    req = responses.calls[1].request
    assert req.headers["Authorization"] == "Bearer scim-tok"
    assert json.loads(req.body)["userName"] == employee.email


@responses.activate
def test_add_to_vault_group_patches_members(op):
    responses.get(
        f"{SCIM}/scim/v2/Groups", json={"Resources": [{"id": "G1", "displayName": "Engineering"}]}
    )
    responses.patch(f"{SCIM}/scim/v2/Groups/G1", json={})
    assert op.add_to_vault_group("U1", "Engineering")["groupId"] == "G1"
    ops = json.loads(responses.calls[1].request.body)["Operations"]
    assert ops == [{"op": "add", "path": "members", "value": [{"value": "U1"}]}]


@responses.activate
def test_add_to_missing_vault_group_fails(op):
    responses.get(f"{SCIM}/scim/v2/Groups", json={"Resources": []})
    with pytest.raises(OnePasswordError, match="does not exist"):
        op.add_to_vault_group("U1", "Nope")


@responses.activate
def test_remove_from_all_vault_groups_and_suspend(op):
    responses.get(
        f"{SCIM}/scim/v2/Users",
        json={
            "Resources": [
                {
                    "id": "U9",
                    "groups": [
                        {"value": "G1", "display": "Engineering"},
                        {"value": "G2", "display": "On-Call"},
                    ],
                }
            ]
        },
    )
    responses.patch(f"{SCIM}/scim/v2/Groups/G1", json={})
    responses.patch(f"{SCIM}/scim/v2/Groups/G2", json={})
    responses.patch(f"{SCIM}/scim/v2/Users/U9", json={})
    removed = op.remove_from_all_vault_groups("bob@mal.example")
    assert removed == ["Engineering", "On-Call"]
    remove_op = json.loads(responses.calls[1].request.body)["Operations"][0]
    assert remove_op == {"op": "remove", "path": 'members[value eq "U9"]'}
    suspend_op = json.loads(responses.calls[3].request.body)["Operations"][0]
    assert suspend_op == {"op": "replace", "path": "active", "value": False}


@responses.activate
def test_remove_reports_partial_failure_but_still_suspends(op):
    responses.get(
        f"{SCIM}/scim/v2/Users",
        json={"Resources": [{"id": "U9", "groups": [{"value": "G1", "display": "Engineering"}]}]},
    )
    responses.patch(f"{SCIM}/scim/v2/Groups/G1", status=500, body="err")
    responses.patch(f"{SCIM}/scim/v2/Users/U9", json={})
    with pytest.raises(OnePasswordError, match="failed"):
        op.remove_from_all_vault_groups("bob@mal.example")
    assert responses.calls[-1].request.url.endswith("/Users/U9")


@responses.activate
def test_audit_events_filtered_to_user(op):
    responses.post(
        f"{EVENTS}/api/v1/auditevents",
        json={
            "items": [
                {"action": "leave", "aux_info": "bob@mal.example"},
                {"action": "join", "aux_info": "someone@else.example"},
            ]
        },
    )
    events = op.recent_audit_events("bob@mal.example")
    assert [e["action"] for e in events] == ["leave"]
    assert responses.calls[0].request.headers["Authorization"] == "Bearer events-tok"
