"""
Data shapes for the three real JFrog Artifactory log sources this tool
reads. Field names and formats here are taken directly from JFrog's own
published documentation (see README's "Real log formats" section for the
exact pages and dates pulled), not invented, and not yet cross-checked
against a live Artifactory instance's actual output -- that gap is called
out explicitly rather than presented as confirmed.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class TokenCreateEvent:
    """One `Event == TKN`, `Event Type == C` row from the Audit Trail Log.

    Audit Trail Log columns, per docs.jfrog.com/administration/docs/audit-trail-log:
    Date | Trace ID | User IP | User | Logged Principal | Entity Name |
    Event Type (C/U/D) | Event (USR/GRP/PRM/TKN) | Data Changed (JSON)
    """
    timestamp: datetime
    trace_id: str
    user_ip: str
    user: str
    logged_principal: str
    entity_name: str
    data_changed_raw: str

    @property
    def looks_admin_scoped(self) -> bool:
        """
        Best-effort only. JFrog's docs confirm the Audit Trail Log records
        token creation (Event=TKN) but do not publish a sample Data Changed
        payload for it, so there is no confirmed field name for token scope
        to key on. This checks for the substring the hypothesis's own scope
        string ("applied-permissions/admin") or a bare "admin" mention,
        which is a heuristic, not a verified schema match.
        """
        return "admin" in self.data_changed_raw.lower()


@dataclass
class LoginEvent:
    """One `[ACCEPTED LOGIN]` row from the Access Log.

    Access Log grammar, per docs.jfrog.com/administration/docs/access-log:
    Timestamp [Trace Id] [Action response and type] Repository path (optional)
    Message (optional) for User/IP type (optional)
    """
    timestamp: datetime
    trace_id: str
    user: str
    ip: str


@dataclass
class RequestLogEntry:
    """One row from router-request.log (the router-fronted API traffic log,
    distinct from the per-repository artifactory-request.log -- this tool
    uses the router log because /access/api/v1/tokens and /api/security/*
    are platform API paths, not repository artifact paths).

    Columns, per the documented sample entry:
    Timestamp | Trace ID | Remote IP | Username | Method | URL | Status |
    Request Content Length | Response Content Length | Duration | User Agent
    """
    timestamp: datetime
    trace_id: str
    remote_ip: str
    username: str
    method: str
    url: str
    status: int
    user_agent: str


@dataclass
class Finding:
    trace_id: str
    source_ip: str
    user: str | None
    token_mint_time: datetime
    verdict: str  # SUPPRESSED | SUSPICIOUS | CONFIRMED
    reasons: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)
