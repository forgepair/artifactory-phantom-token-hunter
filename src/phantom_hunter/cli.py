"""
CLI entrypoint: python -m phantom_hunter --audit-log ... --access-log ... --request-log ...

Exit codes are intended for use in a security pipeline: 0 = nothing found,
1 = SUSPICIOUS findings only, 2 = at least one CONFIRMED finding.
"""
from __future__ import annotations

import argparse
import dataclasses
import json
import sys
from pathlib import Path

from .baseline import load_allowlist
from .correlate import hunt
from .parsers import parse_audit_trail_line, parse_login_event, parse_request_log_line


def _read_lines(path: str) -> list[str]:
    return Path(path).read_text(encoding="utf-8", errors="replace").splitlines()


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="phantom-hunter",
        description="Retro-hunt JFrog Artifactory admin tokens minted without a prior authenticated session (CVE-2026-82329 / HEARTH H294).",
    )
    parser.add_argument("--audit-log", required=True, help="Path to Artifactory's Audit Trail Log")
    parser.add_argument("--access-log", required=True, help="Path to Artifactory's Access Log")
    parser.add_argument("--request-log", required=True, help="Path to router-request.log")
    parser.add_argument("--allowlist", default=None, help="Path to a JSON CI/service-identity allowlist")
    parser.add_argument("--window-minutes", type=int, default=3, help="Enumeration correlation window (default: 3)")
    return parser


def run(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)

    token_events = [e for e in (parse_audit_trail_line(line) for line in _read_lines(args.audit_log)) if e]
    login_events = [e for e in (parse_login_event(line) for line in _read_lines(args.access_log)) if e]
    request_events = [e for e in (parse_request_log_line(line) for line in _read_lines(args.request_log)) if e]
    allowlist = load_allowlist(args.allowlist)

    findings = hunt(token_events, login_events, request_events, allowlist, args.window_minutes)

    print(json.dumps([_finding_to_dict(f) for f in findings], indent=2, default=str))

    if any(f.verdict == "CONFIRMED" for f in findings):
        return 2
    if any(f.verdict == "SUSPICIOUS" for f in findings):
        return 1
    return 0


def _finding_to_dict(finding) -> dict:
    d = dataclasses.asdict(finding)
    d["token_mint_time"] = finding.token_mint_time.isoformat()
    return d


def main() -> None:
    sys.exit(run())


if __name__ == "__main__":
    main()
