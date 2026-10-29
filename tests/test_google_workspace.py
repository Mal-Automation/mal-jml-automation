from unittest.mock import MagicMock

import pytest

from jml.clients.google_workspace import (
    GoogleWorkspaceClient,
    GoogleWorkspaceError,
    generate_temp_password,
)
from jml.config import GoogleConfig

CFG = GoogleConfig("sa.json", "admin@mal.example", "my_customer")


class HttpError404(Exception):
    resp = type("R", (), {"status": 404})()


@pytest.fixture
def svc():
    return MagicMock()


def test_temp_password_is_complex():
    pw = generate_temp_password()
    assert len(pw) == 20
    assert any(c.isupper() for c in pw) and any(c.islower() for c in pw)
    assert any(c.isdigit() for c in pw) and any(not c.isalnum() for c in pw)


def test_create_user_inserts_and_hides_password(svc, employee):
    svc.users().get().execute.side_effect = HttpError404()
    svc.users().insert().execute.return_value = {
        "id": "1",
        "primaryEmail": employee.email,
        "password": "leak",
    }
    client = GoogleWorkspaceClient(CFG, live=True, service=svc)
    user = client.create_user(employee)
    assert "password" not in user
    body = svc.users().insert.call_args.kwargs["body"]
    assert body["primaryEmail"] == employee.email
    assert body["changePasswordAtNextLogin"] is True


def test_create_user_idempotent(svc, employee):
    svc.users().get().execute.return_value = {"id": "existing"}
    client = GoogleWorkspaceClient(CFG, live=True, service=svc)
    assert client.create_user(employee)["id"] == "existing"
    svc.users().insert().execute.assert_not_called()


def test_revoke_oauth_tokens_deletes_each(svc):
    svc.tokens().list().execute.return_value = {
        "items": [
            {"clientId": "a", "displayText": "Slack"},
            {"clientId": "b", "displayText": "Zoom"},
        ]
    }
    client = GoogleWorkspaceClient(CFG, live=True, service=svc)
    revoked = client.revoke_oauth_tokens("bob@mal.example")
    assert [t["clientId"] for t in revoked] == ["a", "b"]
    svc.tokens().delete.assert_any_call(userKey="bob@mal.example", clientId="a")
    svc.tokens().delete.assert_any_call(userKey="bob@mal.example", clientId="b")


def test_revoke_oauth_tokens_reports_partial_failure(svc):
    svc.tokens().list().execute.return_value = {"items": [{"clientId": "a"}, {"clientId": "b"}]}
    svc.tokens().delete().execute.side_effect = [None, RuntimeError("403")]
    client = GoogleWorkspaceClient(CFG, live=True, service=svc)
    with pytest.raises(GoogleWorkspaceError, match="Revoked 1/2"):
        client.revoke_oauth_tokens("bob@mal.example")


def test_sign_out_and_suspend(svc):
    client = GoogleWorkspaceClient(CFG, live=True, service=svc)
    client.sign_out("bob@mal.example")
    client.suspend_user("bob@mal.example")
    svc.users().signOut.assert_called_with(userKey="bob@mal.example")
    svc.users().update.assert_called_with(userKey="bob@mal.example", body={"suspended": True})


def test_mock_mode_uses_fixtures(employee):
    client = GoogleWorkspaceClient(CFG, live=False, service=None)
    assert client.create_user(employee)["primaryEmail"] == employee.email
    assert len(client.revoke_oauth_tokens(employee.email)) == 3
