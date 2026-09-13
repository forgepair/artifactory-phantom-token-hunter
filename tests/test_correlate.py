from datetime import datetime, timezone

from phantom_hunter.baseline import AllowlistEntry
from phantom_hunter.correlate import hunt
from phantom_hunter.models import LoginEvent, RequestLogEntry, TokenCreateEvent

ADMIN_SCOPE = '{"scope":"applied-permissions/admin"}'


def _mint(trace_id, ip, user, ts) -> TokenCreateEvent:
    return TokenCreateEvent(
        timestamp=ts,
        trace_id=trace_id,
        user_ip=ip,
        user=user,
        logged_principal="jffe@000",
        entity_name=f"token-{trace_id}",
        data_changed_raw=ADMIN_SCOPE,
    )


def _req(ip, user, url, ts, method="GET") -> RequestLogEntry:
    return RequestLogEntry(
        timestamp=ts, trace_id="r", remote_ip=ip, username=user, method=method,
        url=url, status=200, user_agent="",
    )


def test_prior_login_by_user_suppresses():
    mint_time = datetime(2026, 9, 10, 2, 0, 5, tzinfo=timezone.utc)
    login_time = datetime(2026, 9, 10, 2, 0, 0, tzinfo=timezone.utc)
    mint = _mint("t1", "10.0.5.20", "ci-service-account", mint_time)
    logins = [LoginEvent(timestamp=login_time, trace_id="l1", user="ci-service-account", ip="10.0.5.20")]
    findings = hunt([mint], logins, [])
    assert len(findings) == 1
    assert findings[0].verdict == "SUPPRESSED"


def test_no_prior_session_and_two_enumeration_hits_confirms():
    mint_time = datetime(2026, 9, 10, 3, 41, 0, tzinfo=timezone.utc)
    mint = _mint("t2", "185.220.101.7", None, mint_time)
    requests = [
        _req("185.220.101.7", None, "api/security/users", datetime(2026, 9, 10, 3, 41, 45, tzinfo=timezone.utc)),
        _req("185.220.101.7", None, "api/security/groups", datetime(2026, 9, 10, 3, 42, 0, tzinfo=timezone.utc)),
    ]
    findings = hunt([mint], [], requests)
    assert len(findings) == 1
    assert findings[0].verdict == "CONFIRMED"
    assert len(findings[0].evidence) == 2


def test_single_enumeration_hit_is_suspicious_not_confirmed():
    mint_time = datetime(2026, 9, 11, 4, 0, 0, tzinfo=timezone.utc)
    mint = _mint("t3", "203.0.113.5", None, mint_time)
    requests = [_req("203.0.113.5", None, "api/security/users", datetime(2026, 9, 11, 4, 0, 30, tzinfo=timezone.utc))]
    findings = hunt([mint], [], requests)
    assert findings[0].verdict == "SUSPICIOUS"


def test_enumeration_outside_window_does_not_confirm():
    mint_time = datetime(2026, 9, 11, 5, 0, 0, tzinfo=timezone.utc)
    mint = _mint("t4", "198.51.100.9", None, mint_time)
    requests = [
        _req("198.51.100.9", None, "api/security/users", datetime(2026, 9, 11, 5, 10, 0, tzinfo=timezone.utc)),
        _req("198.51.100.9", None, "api/security/groups", datetime(2026, 9, 11, 5, 11, 0, tzinfo=timezone.utc)),
    ]
    findings = hunt([mint], [], requests, window_minutes=3)
    assert findings[0].verdict == "SUSPICIOUS"


def test_nat_ip_change_still_suppresses_via_user_match():
    mint_time = datetime(2026, 9, 11, 6, 0, 10, tzinfo=timezone.utc)
    login_time = datetime(2026, 9, 11, 6, 0, 0, tzinfo=timezone.utc)
    mint = _mint("t5", "10.1.1.2", "admin2", mint_time)  # different IP than the login
    logins = [LoginEvent(timestamp=login_time, trace_id="l5", user="admin2", ip="10.1.1.1")]
    findings = hunt([mint], logins, [])
    assert findings[0].verdict == "SUPPRESSED"


def test_baselined_ci_identity_suppresses_even_without_a_login_event():
    mint_time = datetime(2026, 9, 12, 0, 0, 0, tzinfo=timezone.utc)
    mint = _mint("t6", "10.0.5.20", "ci-service-account", mint_time)
    allowlist = [AllowlistEntry(user="ci-service-account", ip_prefix="10.0.5.")]
    findings = hunt([mint], [], [], allowlist)
    assert findings[0].verdict == "SUPPRESSED"
    assert "baselined" in findings[0].reasons[0]


def test_non_admin_scoped_token_mint_is_excluded_entirely():
    mint_time = datetime(2026, 9, 12, 1, 0, 0, tzinfo=timezone.utc)
    mint = TokenCreateEvent(
        timestamp=mint_time, trace_id="t7", user_ip="10.0.0.5", user="jsmith",
        logged_principal="jffe@000", entity_name="token-t7",
        data_changed_raw='{"scope":"repo-read"}',
    )
    findings = hunt([mint], [], [])
    assert findings == []


def test_the_mints_own_request_line_does_not_count_as_its_own_enumeration_evidence():
    mint_time = datetime(2026, 9, 12, 2, 0, 0, tzinfo=timezone.utc)
    mint = _mint("t8", "203.0.113.50", None, mint_time)
    requests = [
        _req("203.0.113.50", None, "access/api/v1/tokens", mint_time, method="POST"),  # the mint itself
        _req("203.0.113.50", None, "api/security/users", datetime(2026, 9, 12, 2, 0, 30, tzinfo=timezone.utc)),
    ]
    findings = hunt([mint], [], requests)
    assert findings[0].verdict == "SUSPICIOUS"  # only 1 real enumeration hit, not 2
