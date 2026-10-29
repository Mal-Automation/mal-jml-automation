"""HTTP session factory with sane retries and secret-safe logging."""

from __future__ import annotations

import logging

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

log = logging.getLogger(__name__)

USER_AGENT = "jml-automation/1.0 (+https://github.com/)"


def build_session(total_retries: int = 3, backoff: float = 0.5) -> requests.Session:
    """Return a session that retries on 429/5xx and honours Retry-After.

    Okta and Google both rate-limit aggressively; 1Password SCIM bridge
    can 503 while it warms up. Retrying idempotent and POST calls is safe here
    because every write in this project is guarded by an existence check.
    """
    retry = Retry(
        total=total_retries,
        backoff_factor=backoff,
        status_forcelist=(429, 500, 502, 503, 504),
        allowed_methods=frozenset({"GET", "POST", "PUT", "PATCH", "DELETE"}),
        respect_retry_after_header=True,
        raise_on_status=False,
    )
    session = requests.Session()
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    session.headers.update({"User-Agent": USER_AGENT, "Accept": "application/json"})
    return session


def redact(value: str | None, keep: int = 4) -> str:
    """Mask a secret for logs: ``00abcdef...`` -> ``****cdef``."""
    if not value:
        return "<unset>"
    return "*" * max(len(value) - keep, 4) + value[-keep:]
