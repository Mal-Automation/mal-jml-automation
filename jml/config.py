"""Configuration loaded exclusively from environment variables.

No credential is ever hardcoded. Each integration decides independently whether
it runs in ``live`` mode (real API) or ``mock`` mode (realistic fixtures):

* ``JML_MODE=mock``  -> every integration is mocked, regardless of credentials.
* ``JML_MODE=live``  -> every integration must be live; missing creds is an error.
* ``JML_MODE=auto``  -> (default) live when that integration's creds are present,
  mocked otherwise. This lets you wire up Okta for real while still mocking Jamf.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field

VALID_MODES = {"auto", "live", "mock"}


class ConfigError(RuntimeError):
    """Raised when required configuration is missing or invalid."""


def _env(name: str, default: str | None = None) -> str | None:
    value = os.environ.get(name, default)
    if value is None:
        return None
    value = value.strip()
    return value or default


@dataclass(frozen=True)
class OktaConfig:
    org_url: str | None
    api_token: str | None

    @property
    def configured(self) -> bool:
        return bool(self.org_url and self.api_token)


@dataclass(frozen=True)
class GoogleConfig:
    service_account_file: str | None
    admin_subject: str | None
    customer_id: str

    @property
    def configured(self) -> bool:
        return bool(self.service_account_file and self.admin_subject)


@dataclass(frozen=True)
class OnePasswordConfig:
    scim_url: str | None
    scim_token: str | None
    events_token: str | None
    events_url: str

    @property
    def configured(self) -> bool:
        return bool(self.scim_url and self.scim_token)


@dataclass(frozen=True)
class JamfConfig:
    url: str | None
    username: str | None
    password: str | None
    invitation_expiry_days: int

    @property
    def configured(self) -> bool:
        return bool(self.url and self.username and self.password)


@dataclass(frozen=True)
class NotifyConfig:
    slack_webhook_url: str | None
    smtp_host: str | None
    smtp_port: int
    smtp_username: str | None
    smtp_password: str | None
    email_from: str | None
    email_to: str | None

    @property
    def slack_configured(self) -> bool:
        return bool(self.slack_webhook_url)

    @property
    def email_configured(self) -> bool:
        return bool(self.smtp_host and self.email_from and self.email_to)


@dataclass(frozen=True)
class Settings:
    mode: str
    okta: OktaConfig
    google: GoogleConfig
    onepassword: OnePasswordConfig
    jamf: JamfConfig
    notify: NotifyConfig
    http_timeout: float = 15.0
    extra: dict = field(default_factory=dict)

    def is_live(self, configured: bool, name: str) -> bool:
        """Decide whether a given integration should hit the real API."""
        if self.mode == "mock":
            return False
        if self.mode == "live":
            if not configured:
                raise ConfigError(
                    f"JML_MODE=live but {name} credentials are not set. " "See .env.example."
                )
            return True
        return configured  # auto


def load_settings() -> Settings:
    """Build :class:`Settings` from the current environment."""
    mode = (_env("JML_MODE", "auto") or "auto").lower()
    if mode not in VALID_MODES:
        raise ConfigError(f"JML_MODE must be one of {sorted(VALID_MODES)}")

    return Settings(
        mode=mode,
        okta=OktaConfig(
            org_url=(_env("OKTA_ORG_URL") or "").rstrip("/") or None,
            api_token=_env("OKTA_API_TOKEN"),
        ),
        google=GoogleConfig(
            service_account_file=_env("GWS_SERVICE_ACCOUNT_FILE"),
            admin_subject=_env("GWS_ADMIN_SUBJECT"),
            customer_id=_env("GWS_CUSTOMER_ID", "my_customer") or "my_customer",
        ),
        onepassword=OnePasswordConfig(
            scim_url=(_env("OP_SCIM_BRIDGE_URL") or "").rstrip("/") or None,
            scim_token=_env("OP_SCIM_TOKEN"),
            events_token=_env("OP_EVENTS_TOKEN"),
            events_url=(
                _env("OP_EVENTS_URL", "https://events.1password.com")
                or "https://events.1password.com"
            ).rstrip("/"),
        ),
        jamf=JamfConfig(
            url=(_env("JAMF_URL") or "").rstrip("/") or None,
            username=_env("JAMF_USERNAME"),
            password=_env("JAMF_PASSWORD"),
            invitation_expiry_days=int(_env("JAMF_INVITATION_EXPIRY_DAYS", "14")),
        ),
        notify=NotifyConfig(
            slack_webhook_url=_env("SLACK_WEBHOOK_URL"),
            smtp_host=_env("SMTP_HOST"),
            smtp_port=int(_env("SMTP_PORT", "587")),
            smtp_username=_env("SMTP_USERNAME"),
            smtp_password=_env("SMTP_PASSWORD"),
            email_from=_env("ALERT_EMAIL_FROM"),
            email_to=_env("ALERT_EMAIL_TO"),
        ),
        http_timeout=float(_env("JML_HTTP_TIMEOUT", "15")),
    )
