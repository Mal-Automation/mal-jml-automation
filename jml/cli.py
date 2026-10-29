"""Command-line entry point.

Examples::

    python -m jml join  --first Ada --last Lovelace --email ada@mal.example
    python -m jml leave --email bob@mal.example
    python -m jml run   --file examples/events.json      # batch / HRIS feed
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from pathlib import Path

from jml.config import ConfigError, load_settings
from jml.models import Employee
from jml.workflow import JMLWorkflow


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="jml", description="Joiner-Mover-Leaver security automation")
    p.add_argument("--mock", action="store_true", help="force every integration into mock mode")
    p.add_argument("-v", "--verbose", action="store_true")
    sub = p.add_subparsers(dest="command", required=True)

    j = sub.add_parser("join", help="onboard a new hire")
    j.add_argument("--first", required=True)
    j.add_argument("--last", required=True)
    j.add_argument("--email", required=True)
    j.add_argument("--department", default="engineering")
    j.add_argument("--title", default="")
    j.add_argument("--manager", default="")
    j.add_argument("--okta-group", default="engineering")
    j.add_argument("--vault-group", default="Engineering")

    lv = sub.add_parser("leave", help="offboard a departing employee")
    lv.add_argument("--email", required=True)
    lv.add_argument("--okta-mode", choices=["suspend", "deactivate"], default="deactivate")

    r = sub.add_parser("run", help="process a JSON file of joiner/leaver events")
    r.add_argument("--file", required=True, type=Path)
    return p


def _load_dotenv() -> None:
    try:
        from dotenv import load_dotenv

        load_dotenv()
    except ImportError:  # pragma: no cover
        pass


def process_events(wf: JMLWorkflow, events: list[dict]) -> list:
    """Run a list of ``{"type": "joiner"|"leaver", ...}`` events in order."""
    reports = []
    for ev in events:
        kind = ev.get("type")
        if kind == "joiner":
            emp_fields = {k: v for k, v in ev.items() if k != "type"}
            reports.append(wf.onboard(Employee(**emp_fields)))
        elif kind == "leaver":
            reports.append(wf.offboard(ev["email"], ev.get("okta_mode", "deactivate")))
        else:
            raise ValueError(f"Unknown event type: {kind!r}")
    return reports


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    _load_dotenv()
    if args.mock:
        os.environ["JML_MODE"] = "mock"
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
    )
    try:
        wf = JMLWorkflow(load_settings())
    except ConfigError as exc:
        logging.error("%s", exc)
        return 2

    if args.command == "join":
        emp = Employee(
            first_name=args.first,
            last_name=args.last,
            email=args.email,
            department=args.department,
            title=args.title,
            manager_email=args.manager,
            okta_group=args.okta_group,
            vault_group=args.vault_group,
        )
        reports = [wf.onboard(emp)]
    elif args.command == "leave":
        reports = [wf.offboard(args.email, args.okta_mode)]
    else:
        events = json.loads(args.file.read_text())
        reports = process_events(wf, events)

    return 0 if all(r.succeeded for r in reports) else 1


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
