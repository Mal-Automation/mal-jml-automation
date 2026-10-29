import pytest

from jml.config import ConfigError, load_settings
from jml.models import ActionResult, Employee, Status, WorkflowReport


def test_auto_mode_is_mock_without_credentials():
    s = load_settings()
    assert s.mode == "auto"
    assert s.is_live(s.okta.configured, "Okta") is False


def test_auto_mode_goes_live_when_credentials_present(monkeypatch):
    monkeypatch.setenv("OKTA_ORG_URL", "https://dev-1.okta.com/")
    monkeypatch.setenv("OKTA_API_TOKEN", "tok")
    s = load_settings()
    assert s.okta.org_url == "https://dev-1.okta.com"  # trailing slash stripped
    assert s.is_live(s.okta.configured, "Okta") is True


def test_live_mode_without_credentials_raises(monkeypatch):
    monkeypatch.setenv("JML_MODE", "live")
    s = load_settings()
    with pytest.raises(ConfigError):
        s.is_live(s.okta.configured, "Okta")


def test_invalid_mode_rejected(monkeypatch):
    monkeypatch.setenv("JML_MODE", "yolo")
    with pytest.raises(ConfigError):
        load_settings()


def test_employee_normalises_and_validates_email(employee):
    assert employee.email == "ada.lovelace@mal.example"
    assert employee.full_name == "Ada Lovelace"
    with pytest.raises(ValueError):
        Employee(first_name="A", last_name="B", email="not-an-email")


def test_report_tracks_failures():
    r = WorkflowReport(event="leaver", user="x@y.z")
    r.add(ActionResult("Okta", "deactivate", Status.SUCCESS))
    assert r.succeeded
    r.add(ActionResult("GWS", "revoke", Status.FAILED, "boom"))
    r.finish()
    assert not r.succeeded
    assert r.to_dict()["results"][1]["status"] == "failed"
    assert r.finished_at is not None
