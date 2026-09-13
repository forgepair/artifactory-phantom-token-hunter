"""
Real pytest suite for the H294 correlation logic in src/detector.py.

Promotes the 6 scenarios that previously only existed as prints inside
detector.py's __main__ block into actual asserted tests, and adds a few
more cases the brief's manual run never exercised: a post-mint login
(must NOT retroactively suppress), and the correlation window's inclusive
boundary.
"""
from detector import detect_h294


def _only(findings, source_ip):
    matches = [f for f in findings if f["source_ip"] == source_ip]
    assert len(matches) == 1, f"expected exactly 1 finding for {source_ip}, got {len(matches)}"
    return matches[0]


def test_legit_ci_service_account_is_suppressed():
    events = [
        {"timestamp": "2026-09-10T02:00:00", "source_ip": "10.0.5.20",
         "event_type": "login", "user": "ci-service-account"},
        {"timestamp": "2026-09-10T02:00:05", "source_ip": "10.0.5.20",
         "event_type": "admin_token_mint", "user": "ci-service-account"},
    ]
    finding = _only(detect_h294(events), "10.0.5.20")
    assert finding["verdict"] == "SUPPRESSED"
    assert "prior authenticated session" in finding["reason"]


def test_legit_human_admin_is_suppressed():
    events = [
        {"timestamp": "2026-09-10T09:15:00", "source_ip": "192.168.1.44",
         "event_type": "login", "user": "jsmith"},
        {"timestamp": "2026-09-10T09:20:00", "source_ip": "192.168.1.44",
         "event_type": "admin_token_mint", "user": "jsmith"},
        {"timestamp": "2026-09-10T09:25:00", "source_ip": "192.168.1.44",
         "event_type": "enumeration", "user": "jsmith"},
    ]
    finding = _only(detect_h294(events), "192.168.1.44")
    assert finding["verdict"] == "SUPPRESSED"


def test_real_malicious_sequence_is_confirmed():
    events = [
        {"timestamp": "2026-09-10T03:41:00", "source_ip": "185.220.101.7",
         "event_type": "admin_token_mint", "user": None},
        {"timestamp": "2026-09-10T03:41:45", "source_ip": "185.220.101.7",
         "event_type": "enumeration", "user": None},
        {"timestamp": "2026-09-10T03:42:30", "source_ip": "185.220.101.7",
         "event_type": "account_creation", "user": "svc_a1b2c3d4"},
    ]
    finding = _only(detect_h294(events), "185.220.101.7")
    assert finding["verdict"] == "CONFIRMED"
    assert len(finding["evidence"]) == 2


def test_single_followup_event_is_suspicious_not_confirmed():
    """>=2 events required -- a lone follow-up must not over-fire CONFIRMED."""
    events = [
        {"timestamp": "2026-09-11T04:00:00", "source_ip": "203.0.113.5",
         "event_type": "admin_token_mint", "user": None},
        {"timestamp": "2026-09-11T04:00:30", "source_ip": "203.0.113.5",
         "event_type": "enumeration", "user": None},
    ]
    finding = _only(detect_h294(events), "203.0.113.5")
    assert finding["verdict"].startswith("SUSPICIOUS")
    assert len(finding["evidence"]) == 1


def test_followups_outside_correlation_window_do_not_confirm():
    events = [
        {"timestamp": "2026-09-11T05:00:00", "source_ip": "198.51.100.9",
         "event_type": "admin_token_mint", "user": None},
        {"timestamp": "2026-09-11T05:10:00", "source_ip": "198.51.100.9",
         "event_type": "enumeration", "user": None},
        {"timestamp": "2026-09-11T05:11:00", "source_ip": "198.51.100.9",
         "event_type": "account_creation", "user": "x"},
    ]
    finding = _only(detect_h294(events, correlation_window_minutes=3), "198.51.100.9")
    assert finding["verdict"].startswith("SUSPICIOUS")
    assert finding["evidence"] == []


def test_nat_load_balancer_ip_change_is_suppressed_via_user_identity():
    """
    The real false-positive mode the brief found by testing v1 (pure
    IP-keyed correlation): a legit admin logs in from one IP, but the
    mint call arrives from a different IP (NAT/load balancer). Must be
    suppressed via user-identity correlation, not flagged.
    """
    events = [
        {"timestamp": "2026-09-11T06:00:00", "source_ip": "10.1.1.1",
         "event_type": "login", "user": "admin2"},
        {"timestamp": "2026-09-11T06:00:10", "source_ip": "10.1.1.2",
         "event_type": "admin_token_mint", "user": "admin2"},
    ]
    finding = _only(detect_h294(events), "10.1.1.2")
    assert finding["verdict"] == "SUPPRESSED"


def test_login_after_the_mint_does_not_retroactively_suppress():
    """
    An attacker who mints first and logs in afterward (e.g. to look
    legitimate, or via a stolen credential used opportunistically) must
    still be flagged -- only a PRIOR session suppresses.
    """
    events = [
        {"timestamp": "2026-09-12T01:00:00", "source_ip": "203.0.113.99",
         "event_type": "admin_token_mint", "user": "svc_x"},
        {"timestamp": "2026-09-12T01:00:20", "source_ip": "203.0.113.99",
         "event_type": "enumeration", "user": "svc_x"},
        {"timestamp": "2026-09-12T01:00:40", "source_ip": "203.0.113.99",
         "event_type": "account_creation", "user": "svc_x"},
        {"timestamp": "2026-09-12T01:05:00", "source_ip": "203.0.113.99",
         "event_type": "login", "user": "svc_x"},
    ]
    finding = _only(detect_h294(events), "203.0.113.99")
    assert finding["verdict"] == "CONFIRMED"


def test_followup_exactly_at_window_boundary_counts():
    """The window is inclusive at its end (mint_time <= t <= window_end)."""
    events = [
        {"timestamp": "2026-09-12T02:00:00", "source_ip": "203.0.113.50",
         "event_type": "admin_token_mint", "user": None},
        {"timestamp": "2026-09-12T02:03:00", "source_ip": "203.0.113.50",
         "event_type": "enumeration", "user": None},
        {"timestamp": "2026-09-12T02:03:00", "source_ip": "203.0.113.50",
         "event_type": "account_creation", "user": None},
    ]
    finding = _only(detect_h294(events, correlation_window_minutes=3), "203.0.113.50")
    assert finding["verdict"] == "CONFIRMED"


def test_no_admin_token_mint_events_produces_no_findings():
    events = [
        {"timestamp": "2026-09-12T03:00:00", "source_ip": "10.0.0.1",
         "event_type": "login", "user": "jsmith"},
        {"timestamp": "2026-09-12T03:05:00", "source_ip": "10.0.0.1",
         "event_type": "enumeration", "user": "jsmith"},
    ]
    assert detect_h294(events) == []
