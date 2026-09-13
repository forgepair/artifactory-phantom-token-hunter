from datetime import datetime, timezone

from phantom_hunter.enumeration import is_enumeration_request
from phantom_hunter.models import RequestLogEntry


def _req(url: str, method: str = "GET") -> RequestLogEntry:
    return RequestLogEntry(
        timestamp=datetime(2026, 9, 10, tzinfo=timezone.utc),
        trace_id="t",
        remote_ip="1.2.3.4",
        username="x",
        method=method,
        url=url,
        status=200,
        user_agent="",
    )


def test_flags_named_h294_enumeration_endpoints():
    assert is_enumeration_request(_req("api/security/users"))
    assert is_enumeration_request(_req("api/security/groups"))
    assert is_enumeration_request(_req("api/security/permissions"))
    assert is_enumeration_request(_req("access/api/v1/federation/status"))
    assert is_enumeration_request(_req("access/api/v1/credential-sets"))


def test_does_not_flag_the_mint_endpoint_itself():
    # The token-creation call itself must never count as its own follow-up
    # enumeration evidence.
    assert not is_enumeration_request(_req("access/api/v1/tokens", method="POST"))


def test_does_not_flag_unrelated_endpoints():
    assert not is_enumeration_request(_req("api/repositories"))
    assert not is_enumeration_request(_req("api/v1/cert/root"))
