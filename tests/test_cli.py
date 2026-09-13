"""
End-to-end CLI test: writes real-log-shaped files to disk (audit trail,
access, request logs, plus a CI allowlist), invokes the actual CLI entry
point, and checks both the exit code and the JSON it prints.
"""
import json

import pytest

from phantom_hunter.cli import run

AUDIT_LOG = """\
2026-09-13T01:00:00.000Z|trace-ci|10.0.5.20|ci-service-account|jffe@000|token-ci|C|TKN|{"scope":"applied-permissions/admin"}
2026-09-13T02:00:00.000Z|trace-mal|203.0.113.7|unknown|jffe@000|token-mal|C|TKN|{"scope":"applied-permissions/admin"}
2026-09-13T02:05:00.000Z|trace-usr|10.0.0.1|admin|jffe@000|newuser|C|USR|{}
"""

ACCESS_LOG = """\
2020-05-15 15:52:11,456 [4b1b8a0b04e31b80] [ACCEPTED DOWNLOAD] maven-remote-cache:org/iostreams/iostreams/0.2/iostreams-0.2.jar for anonymous/86.12.14.192.
"""

REQUEST_LOG = """\
2026-09-13T02:00:00.000Z|trace-mal|203.0.113.7|unknown|POST|access/api/v1/tokens|201|0|20|2|python-requests/2.0
2026-09-13T02:00:30.000Z|r1|203.0.113.7|unknown|GET|api/security/users|200|0|10|1|curl/8.0
2026-09-13T02:01:00.000Z|r2|203.0.113.7|unknown|GET|api/security/groups|200|0|10|1|curl/8.0
"""

ALLOWLIST = json.dumps([{"user": "ci-service-account", "ip_prefix": "10.0.5."}])


@pytest.fixture
def log_files(tmp_path):
    paths = {}
    for name, content in [("audit", AUDIT_LOG), ("access", ACCESS_LOG), ("request", REQUEST_LOG)]:
        p = tmp_path / f"{name}.log"
        p.write_text(content, encoding="utf-8")
        paths[name] = str(p)
    allowlist_path = tmp_path / "allowlist.json"
    allowlist_path.write_text(ALLOWLIST, encoding="utf-8")
    paths["allowlist"] = str(allowlist_path)
    return paths


def test_cli_confirms_the_malicious_mint_and_suppresses_the_baselined_ci_one(log_files, capsys):
    exit_code = run([
        "--audit-log", log_files["audit"],
        "--access-log", log_files["access"],
        "--request-log", log_files["request"],
        "--allowlist", log_files["allowlist"],
    ])
    out = capsys.readouterr().out
    findings = json.loads(out)

    assert exit_code == 2  # a CONFIRMED finding is present
    assert len(findings) == 2

    by_trace = {f["trace_id"]: f for f in findings}
    assert by_trace["trace-ci"]["verdict"] == "SUPPRESSED"
    assert by_trace["trace-mal"]["verdict"] == "CONFIRMED"
    assert len(by_trace["trace-mal"]["evidence"]) == 2


def test_cli_without_allowlist_still_confirms_malicious_and_flags_ci_as_suspicious(log_files, capsys):
    # No allowlist passed -- the CI mint now has no way to be suppressed
    # (no login event for it either), so it should surface as SUSPICIOUS
    # rather than silently vanishing. This is the exact gap the allowlist
    # mechanism exists to close.
    exit_code = run([
        "--audit-log", log_files["audit"],
        "--access-log", log_files["access"],
        "--request-log", log_files["request"],
    ])
    findings = json.loads(capsys.readouterr().out)
    by_trace = {f["trace_id"]: f for f in findings}

    assert exit_code == 2
    assert by_trace["trace-ci"]["verdict"] == "SUSPICIOUS"
    assert by_trace["trace-mal"]["verdict"] == "CONFIRMED"
