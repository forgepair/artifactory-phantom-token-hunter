"""
CI/service-identity baselining -- H294's own author-named top
false-positive mitigation: "Known CI service principals show stable
recurring identities, internal or allowlisted source IPs, narrow
repository-scoped permissions, and predictable schedules; baseline these
and suppress them explicitly rather than suppressing the token endpoint."

This module implements the allowlist side of that: a small JSON file naming
known-stable service identities, so a real deployment doesn't have to rely
solely on "did this identity ever log in before" (detector.py's original
proof-of-mechanism heuristic) to avoid flagging routine CI token minting.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path


@dataclass
class AllowlistEntry:
    user: str
    ip_prefix: str | None = None  # e.g. "10.0.5." -- simple prefix match, not full CIDR


def load_allowlist(path: str | Path | None) -> list[AllowlistEntry]:
    if path is None:
        return []
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    return [AllowlistEntry(user=entry["user"], ip_prefix=entry.get("ip_prefix")) for entry in data]


def is_baselined(user: str | None, ip: str, allowlist: list[AllowlistEntry]) -> bool:
    if not user:
        return False
    for entry in allowlist:
        if entry.user != user:
            continue
        if entry.ip_prefix is None or ip.startswith(entry.ip_prefix):
            return True
    return False
