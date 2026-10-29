import json
from unittest.mock import MagicMock, patch

import requests
import responses

from jml.config import NotifyConfig
from jml.models import ActionResult, Status, WorkflowReport
from jml.notify import Notifier, build_slack_payload, format_text

HOOK = "https://hooks.slack.com/services/T000/B000/XXXX"


def _report(fail=False):
    r = WorkflowReport(event="leaver", user="bob@mal.example")
    r.add(ActionResult("Okta", "deactivate", Status.SUCCESS, "ok"))
    if fail:
        r.add(ActionResult("1Password", "remove vaults", Status.FAILED, "HTTP 500"))
    return r.finish()


def _cfg(**kw):
    base = dict(
        slack_webhook_url=None,
        smtp_host=None,
        smtp_port=587,
        smtp_username=None,
        smtp_password=None,
        email_from=None,
        email_to=None,
    )
    base.update(kw)
    return NotifyConfig(**base)


def test_slack_payload_contains_user_timestamp_actions_failures():
    payload = build_slack_payload(_report(fail=True))
    dumped = json.dumps(payload)
    assert "bob@mal.example" in dumped
    assert "Timestamp" in dumped
    assert "Okta" in dumped and "Needs follow-up" in dumped
    assert payload["blocks"][0]["type"] == "header"


@responses.activate
def test_notify_posts_to_slack_webhook():
    responses.post(HOOK, body="ok")
    sent = Notifier(_cfg(slack_webhook_url=HOOK), session=requests.Session()).notify(_report())
    assert sent == ["slack"]
    assert json.loads(responses.calls[0].request.body)["text"].endswith("bob@mal.example")


@responses.activate
def test_slack_failure_falls_back_to_console(capsys):
    responses.post(HOOK, status=404, body="no_service")
    sent = Notifier(_cfg(slack_webhook_url=HOOK), session=requests.Session()).notify(_report())
    assert sent == ["console"]
    assert "JML LEAVER" in capsys.readouterr().out


def test_email_alert_sent_via_smtp():
    cfg = _cfg(
        smtp_host="smtp.mal.example",
        smtp_username="u",
        smtp_password="p",
        email_from="jml@mal.example",
        email_to="sec@mal.example",
    )
    with patch("jml.notify.smtplib.SMTP") as smtp_cls:
        smtp = MagicMock()
        smtp_cls.return_value.__enter__.return_value = smtp
        assert Notifier(cfg).notify(_report(fail=True)) == ["email"]
    msg = smtp.send_message.call_args.args[0]
    assert "FAILURES" in msg["Subject"]
    smtp.starttls.assert_called_once()
    smtp.login.assert_called_once_with("u", "p")


def test_text_format_lists_failures():
    assert "manual follow-up" in format_text(_report(fail=True))
