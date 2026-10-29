import json
from unittest.mock import MagicMock

import pytest

from jml.cli import main
from jml.clients.okta import OktaError
from jml.models import Status
from jml.workflow import JMLWorkflow


@pytest.fixture
def notifier():
    n = MagicMock()
    n.notify.return_value = ["console"]
    return n


def test_onboard_all_steps_succeed_in_mock(mock_settings, employee, notifier, tmp_path):
    wf = JMLWorkflow(mock_settings, notifier=notifier, report_dir=tmp_path)
    report = wf.onboard(employee)
    assert report.succeeded
    systems = {r.system for r in report.results}
    assert systems == {"Okta", "Google Workspace", "1Password", "Jamf (MDM)"}
    assert all(r.mocked for r in report.results)
    assert len(list(tmp_path.glob("joiner-*.json"))) == 1


def test_onboard_skips_group_when_okta_create_fails(mock_settings, employee, notifier, tmp_path):
    wf = JMLWorkflow(mock_settings, notifier=notifier, report_dir=tmp_path)
    wf.okta.create_user = MagicMock(side_effect=OktaError("HTTP 400"))
    report = wf.onboard(employee)
    statuses = [(r.system, r.status) for r in report.results if r.system == "Okta"]
    assert statuses == [("Okta", Status.FAILED), ("Okta", Status.SKIPPED)]
    assert not report.succeeded
    # other systems still provisioned
    assert any(r.system == "Jamf (MDM)" and r.status is Status.SUCCESS for r in report.results)


def test_offboard_continues_after_failure_and_alerts(mock_settings, notifier, tmp_path):
    wf = JMLWorkflow(mock_settings, notifier=notifier, report_dir=tmp_path)
    wf.okta.offboard = MagicMock(side_effect=OktaError("HTTP 503"))
    report = wf.offboard("bob@mal.example")
    assert report.failures[0].system == "Okta"
    assert any(r.action == "revoke all OAuth tokens" and r.ok for r in report.results)
    assert any(r.system == "1Password" and "vault" in r.action and r.ok for r in report.results)
    notifier.notify.assert_called_once_with(report)
    saved = json.loads(next(tmp_path.glob("leaver-*.json")).read_text())
    assert saved["succeeded"] is False


def test_cli_batch_run_returns_zero(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    events = tmp_path / "events.json"
    events.write_text(
        json.dumps(
            [
                {"type": "joiner", "first_name": "A", "last_name": "B", "email": "a@b.co"},
                {"type": "leaver", "email": "c@d.co"},
            ]
        )
    )
    assert main(["--mock", "run", "--file", str(events)]) == 0
    assert "JML LEAVER COMPLETED" in capsys.readouterr().out


def test_cli_live_mode_without_creds_exits_2(monkeypatch):
    monkeypatch.setenv("JML_MODE", "live")
    assert main(["leave", "--email", "x@y.co"]) == 2
