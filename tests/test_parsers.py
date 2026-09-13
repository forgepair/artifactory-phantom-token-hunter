"""
Parser tests, anchored to JFrog's own documented sample lines where one
exists (the request-log DOWNLOAD/cert sample is real, pulled verbatim from
docs.jfrog.com); the audit-trail and LOGIN samples are constructed by hand
in the documented column order/grammar, since JFrog's docs describe the
format but do not publish a token-creation or LOGIN sample line.
"""
from phantom_hunter.parsers import parse_audit_trail_line, parse_login_event, parse_request_log_line


def test_parses_a_real_documented_request_log_sample_line():
    # Pulled verbatim from JFrog's own docs (router-request.log example).
    line = '2025-04-18T15:39:04.902Z|d5d75b3c41242768|127.0.0.1|anonymous|GET|api/v1/cert/root|200|0|6|0|JFrog Access Java Client/x.y.z.'
    entry = parse_request_log_line(line)
    assert entry is not None
    assert entry.trace_id == "d5d75b3c41242768"
    assert entry.remote_ip == "127.0.0.1"
    assert entry.username == "anonymous"
    assert entry.method == "GET"
    assert entry.url == "api/v1/cert/root"
    assert entry.status == 200


def test_request_log_line_with_too_few_fields_is_rejected():
    assert parse_request_log_line("garbage|not|a|real|line") is None


def test_parses_accepted_login_line_iso_timestamp():
    line = "2026-09-10T09:15:00.000Z [abc123def456] [ACCEPTED LOGIN] for jsmith/192.168.1.44."
    event = parse_login_event(line)
    assert event is not None
    assert event.user == "jsmith"
    assert event.ip == "192.168.1.44"
    assert event.trace_id == "abc123def456"


def test_parses_accepted_login_line_comma_millis_timestamp():
    # JFrog's own docs give this timestamp shape in their sample DOWNLOAD
    # line even though the field spec elsewhere claims RFC-3339 -- both
    # must parse.
    line = "2020-05-15 15:52:11,456 [4b1b8a0b04e31b80] [ACCEPTED LOGIN] for admin2/86.12.14.192."
    event = parse_login_event(line)
    assert event is not None
    assert event.user == "admin2"
    assert event.ip == "86.12.14.192"


def test_real_documented_download_sample_is_not_a_login_event():
    # Pulled verbatim from JFrog's own docs -- an accepted DOWNLOAD, not a
    # login, and must not be misclassified as one.
    line = (
        "2020-05-15 15:52:11,456 [4b1b8a0b04e31b80] [ACCEPTED DOWNLOAD] "
        "maven-remote-cache:org/iostreams/iostreams/0.2/iostreams-0.2.jar "
        "for anonymous/86.12.14.192."
    )
    assert parse_login_event(line) is None


def test_denied_login_is_not_a_prior_session():
    line = "2026-09-10T09:15:00.000Z [abc123] [DENIED LOGIN] for attacker/203.0.113.9."
    assert parse_login_event(line) is None


def test_parses_token_create_row_from_audit_trail():
    line = '2026-09-10T03:41:00.000Z|a1b2c3d4e5f6a7b8|185.220.101.7|unknown|jffe@000|token-abc123|C|TKN|{"scope":"applied-permissions/admin"}'
    event = parse_audit_trail_line(line)
    assert event is not None
    assert event.trace_id == "a1b2c3d4e5f6a7b8"
    assert event.user_ip == "185.220.101.7"
    assert event.looks_admin_scoped is True


def test_non_admin_scoped_token_create_is_parsed_but_not_flagged_admin():
    line = '2026-09-10T03:41:00.000Z|trace2|10.0.0.5|jsmith|jffe@000|token-def456|C|TKN|{"scope":"repo-read"}'
    event = parse_audit_trail_line(line)
    assert event is not None
    assert event.looks_admin_scoped is False


def test_non_token_audit_rows_are_ignored():
    # Event == USR (user creation), not TKN -- irrelevant to this hunt.
    line = "2026-09-10T03:41:00.000Z|trace3|10.0.0.5|admin|jffe@000|newuser|C|USR|{}"
    assert parse_audit_trail_line(line) is None


def test_token_update_or_delete_rows_are_ignored():
    # Only Event Type 'C' (Create) counts as a mint.
    line = '2026-09-10T03:41:00.000Z|trace4|10.0.0.5|admin|jffe@000|token-abc123|D|TKN|{"scope":"applied-permissions/admin"}'
    assert parse_audit_trail_line(line) is None
