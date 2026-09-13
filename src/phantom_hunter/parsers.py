"""
Parsers for the three real JFrog Artifactory log formats this tool reads.
Each parser is defensive: a line that doesn't match the documented grammar
returns None rather than raising, since real log files always carry lines
(warnings, multi-line stack traces, unrelated action types) outside the one
shape a given parser targets.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone

from .models import LoginEvent, RequestLogEntry, TokenCreateEvent


def _parse_timestamp(raw: str) -> datetime | None:
    """
    JFrog's own docs are internally inconsistent about the access-log
    timestamp format: the field definition states RFC-3339
    (`yyyy-MM-dd'T'HH:mm:ss.SSSZ`), but the documentation's own sample line
    uses `yyyy-MM-dd HH:mm:ss,SSS` (comma millis, no 'T'/'Z'). Both are
    accepted here rather than picking one and silently dropping real lines
    in the other shape.
    """
    raw = raw.strip()
    iso_candidate = raw.replace("Z", "+00:00") if raw.endswith("Z") else raw
    try:
        return datetime.fromisoformat(iso_candidate)
    except ValueError:
        pass
    try:
        naive = datetime.strptime(raw, "%Y-%m-%d %H:%M:%S,%f")
        return naive.replace(tzinfo=timezone.utc)
    except ValueError:
        return None


# Access Log grammar (docs.jfrog.com/administration/docs/access-log):
#   Timestamp [Trace Id] [Action-response Action-type] Repo-path(optional)
#   for User/IP Type(optional).
_ACCESS_LOG_RE = re.compile(
    r"^(?P<ts>\S+(?:[ T]\S+))\s+"
    r"\[(?P<trace>[^\]]+)\]\s+"
    r"\[(?P<response>ACCEPTED|DENIED)\s+(?P<action>[A-Z_]+)\]\s+"
    r"(?:(?P<repo>\S+)\s+)?"
    r"for\s+(?P<user>[^/\s]+)/(?P<ip>[0-9a-fA-F:.]+)"
    r"(?:\s+(?P<authtype>APIKEY|TOKEN))?\.?\s*$"
)


def parse_login_event(line: str) -> LoginEvent | None:
    """Extracts a LOGIN row from an access-log line, or None for any other
    line (a different action type, a DENIED response, or unparseable)."""
    match = _ACCESS_LOG_RE.match(line.strip())
    if not match:
        return None
    if match.group("response") != "ACCEPTED" or match.group("action") != "LOGIN":
        return None
    ts = _parse_timestamp(match.group("ts"))
    if ts is None:
        return None
    return LoginEvent(
        timestamp=ts,
        trace_id=match.group("trace"),
        user=match.group("user"),
        ip=match.group("ip").rstrip("."),  # the IP char class also matches the sentence-ending "."
    )


def parse_request_log_line(line: str) -> RequestLogEntry | None:
    """
    router-request.log grammar (pipe-separated, 11 fields):
    Timestamp|TraceID|RemoteIP|Username|Method|URL|Status|ReqLen|RespLen|Duration|UserAgent
    """
    parts = line.rstrip("\n").split("|")
    if len(parts) < 7:
        return None
    ts = _parse_timestamp(parts[0])
    if ts is None:
        return None
    try:
        status = int(parts[6])
    except ValueError:
        return None
    return RequestLogEntry(
        timestamp=ts,
        trace_id=parts[1],
        remote_ip=parts[2],
        username=parts[3],
        method=parts[4],
        url=parts[5],
        status=status,
        user_agent=parts[10] if len(parts) > 10 else "",
    )


def parse_audit_trail_line(line: str) -> TokenCreateEvent | None:
    """
    Audit Trail Log grammar (pipe-separated, 9 fields):
    Date|Trace ID|User IP|User|Logged Principal|Entity Name|Event Type|Event|Data Changed
    Only Event Type == 'C' (Create) and Event == 'TKN' (Token) rows -- i.e.
    token-creation events -- are surfaced; every other row returns None.
    """
    parts = line.rstrip("\n").split("|", maxsplit=8)
    if len(parts) < 9:
        return None
    date_raw, trace_id, user_ip, user, logged_principal, entity_name, event_type, event, data_changed = parts
    if event.strip() != "TKN" or event_type.strip() != "C":
        return None
    ts = _parse_timestamp(date_raw)
    if ts is None:
        return None
    return TokenCreateEvent(
        timestamp=ts,
        trace_id=trace_id,
        user_ip=user_ip,
        user=user,
        logged_principal=logged_principal,
        entity_name=entity_name,
        data_changed_raw=data_changed,
    )
