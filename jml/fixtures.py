"""Load realistic mock API responses from ``fixtures/*.json``.

Fixtures are templates: ``{{email}}``, ``{{first_name}}`` etc. are substituted
so mocked responses look exactly like the vendor's real payload for that user.
"""

from __future__ import annotations

import copy
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

FIXTURE_DIR = Path(__file__).resolve().parent.parent / "fixtures"


def _render(obj: Any, ctx: dict[str, str]) -> Any:
    if isinstance(obj, str):
        for key, val in ctx.items():
            obj = obj.replace("{{" + key + "}}", str(val))
        return obj
    if isinstance(obj, list):
        return [_render(i, ctx) for i in obj]
    if isinstance(obj, dict):
        return {k: _render(v, ctx) for k, v in obj.items()}
    return obj


def load_fixture(name: str, **ctx: str) -> Any:
    """Load ``fixtures/<name>.json`` and substitute template variables."""
    path = FIXTURE_DIR / f"{name}.json"
    with path.open(encoding="utf-8") as fh:
        data = json.load(fh)
    base = {
        "now": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
        "uuid": uuid.uuid4().hex,
    }
    base.update(ctx)
    return _render(copy.deepcopy(data), base)
