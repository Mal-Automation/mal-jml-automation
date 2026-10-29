"""Shared data structures for the JML workflow."""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


class Status(str, Enum):
    SUCCESS = "success"
    FAILED = "failed"
    SKIPPED = "skipped"


@dataclass
class Employee:
    """A person moving through the identity lifecycle."""

    first_name: str
    last_name: str
    email: str
    department: str = "engineering"
    title: str = ""
    manager_email: str = ""
    okta_group: str = "engineering"
    vault_group: str = "Engineering"

    def __post_init__(self) -> None:
        self.email = self.email.strip().lower()
        if not EMAIL_RE.match(self.email):
            raise ValueError(f"Invalid email address: {self.email!r}")
        if not self.first_name.strip() or not self.last_name.strip():
            raise ValueError("first_name and last_name are required")

    @property
    def full_name(self) -> str:
        return f"{self.first_name} {self.last_name}"


@dataclass
class ActionResult:
    """Outcome of a single security-relevant step."""

    system: str
    action: str
    status: Status
    detail: str = ""
    mocked: bool = False
    data: dict = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return self.status is not Status.FAILED

    def to_dict(self) -> dict:
        d = asdict(self)
        d["status"] = self.status.value
        return d


@dataclass
class WorkflowReport:
    """Aggregated result of a joiner or leaver run."""

    event: str  # "joiner" | "leaver"
    user: str
    started_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(timespec="seconds")
    )
    finished_at: str | None = None
    results: list[ActionResult] = field(default_factory=list)

    def add(self, result: ActionResult) -> ActionResult:
        self.results.append(result)
        return result

    def finish(self) -> WorkflowReport:
        self.finished_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
        return self

    @property
    def failures(self) -> list[ActionResult]:
        return [r for r in self.results if r.status is Status.FAILED]

    @property
    def succeeded(self) -> bool:
        return not self.failures

    def to_dict(self) -> dict:
        return {
            "event": self.event,
            "user": self.user,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "succeeded": self.succeeded,
            "results": [r.to_dict() for r in self.results],
        }
