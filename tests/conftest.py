import pytest

from jml.config import load_settings
from jml.models import Employee

ENV_PREFIXES = ("JML_", "OKTA_", "GWS_", "OP_", "JAMF_", "SLACK_", "SMTP_", "ALERT_")


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    """Isolate every test from the developer's real credentials."""
    import os

    for key in list(os.environ):
        if key.startswith(ENV_PREFIXES):
            monkeypatch.delenv(key, raising=False)
    # stop python-dotenv from re-reading a local .env during CLI tests
    monkeypatch.setattr("dotenv.load_dotenv", lambda *a, **k: False, raising=False)


@pytest.fixture
def employee():
    return Employee(
        first_name="Ada",
        last_name="Lovelace",
        email="Ada.Lovelace@mal.example",
        title="Engineer",
    )


@pytest.fixture
def mock_settings(monkeypatch):
    monkeypatch.setenv("JML_MODE", "mock")
    return load_settings()
