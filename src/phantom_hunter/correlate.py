"""
The actual H294 correlation, run against parsed real-log-shaped events
instead of a single flat synthetic event stream (that was detector.py's
original proof-of-mechanism, kept as-is for continuity).

Per H294's own text: "Pivot: join enumeration requests to the minting
event by source IP address, authorization subject, and user agent."
This implementation joins on source IP OR username (either is sufficient),
matching detector.py's precedent of surviving a NAT/load-balancer IP
change between a login and a later API call from the same identity.
"""
from __future__ import annotations

from datetime import timedelta

from .baseline import AllowlistEntry, is_baselined
from .enumeration import is_enumeration_request
from .models import Finding, LoginEvent, RequestLogEntry, TokenCreateEvent

MIN_BURST_EVENTS_TO_CONFIRM = 2


def hunt(
    token_events: list[TokenCreateEvent],
    login_events: list[LoginEvent],
    request_events: list[RequestLogEntry],
    allowlist: list[AllowlistEntry] | None = None,
    window_minutes: int = 3,
) -> list[Finding]:
    allowlist = allowlist or []
    findings: list[Finding] = []

    for mint in token_events:
        if not mint.looks_admin_scoped:
            continue  # H294's own filter scopes to admin-permission tokens

        if is_baselined(mint.user, mint.user_ip, allowlist):
            findings.append(
                Finding(
                    trace_id=mint.trace_id,
                    source_ip=mint.user_ip,
                    user=mint.user,
                    token_mint_time=mint.timestamp,
                    verdict="SUPPRESSED",
                    reasons=[f"'{mint.user}' at {mint.user_ip} is an allowlisted/baselined CI identity"],
                )
            )
            continue

        prior_logins = [
            login
            for login in login_events
            if login.timestamp < mint.timestamp
            and (login.user == mint.user or login.ip == mint.user_ip)
        ]
        if prior_logins:
            latest = max(prior_logins, key=lambda login: login.timestamp)
            findings.append(
                Finding(
                    trace_id=mint.trace_id,
                    source_ip=mint.user_ip,
                    user=mint.user,
                    token_mint_time=mint.timestamp,
                    verdict="SUPPRESSED",
                    reasons=[f"prior authenticated session (user or IP match) at {latest.timestamp.isoformat()}"],
                )
            )
            continue

        window_end = mint.timestamp + timedelta(minutes=window_minutes)
        followups = [
            req
            for req in request_events
            if mint.timestamp <= req.timestamp <= window_end
            and (req.remote_ip == mint.user_ip or req.username == mint.user)
            and is_enumeration_request(req)
        ]

        verdict = "CONFIRMED" if len(followups) >= MIN_BURST_EVENTS_TO_CONFIRM else "SUSPICIOUS"
        findings.append(
            Finding(
                trace_id=mint.trace_id,
                source_ip=mint.user_ip,
                user=mint.user,
                token_mint_time=mint.timestamp,
                verdict=verdict,
                reasons=[
                    "no prior authenticated session; "
                    + (
                        f"{len(followups)} enumeration hits within {window_minutes}m confirms the malicious pattern"
                        if verdict == "CONFIRMED"
                        else "insufficient follow-up burst to confirm"
                    )
                ],
                evidence=[f"{req.method} {req.url} at {req.timestamp.isoformat()}" for req in followups],
            )
        )

    return findings
