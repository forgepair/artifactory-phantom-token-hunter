"""
Proof-of-mechanism for THORCollective/HEARTH hypothesis H294:
"Artifactory Admin Token Minting Without Prior Authenticated Session"

Context: CVE-2026-82329 (JFrog Artifactory blank cluster-join-key auth
bypass) lets an attacker mint a fully-privileged admin token with NO
prior authenticated session. H294 (submitted by practitioner Joshua
Strickland) proposes detecting this retroactively by correlating:
  1. An admin-scope token mint with no prior authenticated session
     from that identity/source.
  2. A burst of enumeration/account-creation events within a short
     window immediately after the mint.

Patching CVE-2026-82329 does NOT evict tokens already minted before
the patch -- this is a retro-hunt mechanism for already-compromised
instances, not a preventive check.

No executable open-source tool operationalizing this correlation was
found anywhere (checked via GitHub repo/code search, 2026-09-13) --
this is a real, currently-unfilled gap. This script is a first working
proof that the core correlation logic is sound, run against synthetic
data modeling real JFrog Artifactory log fields (per JFrog's own docs:
timestamp, source IP, action type, user).

STATUS: proof-of-mechanism only, run against synthetic data. NOT yet
tested against real Artifactory access logs. See BRIEF.md (not yet
written) for scope/demand caveats before treating this as a product.
"""
from datetime import datetime, timedelta


def parse_ts(ts):
    return datetime.fromisoformat(ts)


def detect_h294(events, correlation_window_minutes=3):
    """
    events: list of dicts with fields:
      - timestamp (ISO str)
      - source_ip
      - event_type: one of 'login', 'admin_token_mint', 'enumeration',
        'account_creation'
      - user (optional -- correlates on user identity too, not just
        IP, to survive NAT/load-balancer IP changes between a login
        and a later API call from the same legitimate identity; a
        real false-positive mode found by testing v1 of this logic)

    Returns a list of findings, one per admin_token_mint event:
      SUPPRESSED  -- a prior authenticated session (by IP or user)
                     exists before the mint; not suspicious.
      CONFIRMED   -- no prior session, AND >=2 enumeration/account-
                     creation events follow within the correlation
                     window -- matches the malicious pattern.
      SUSPICIOUS  -- no prior session, but insufficient follow-up
                     burst to confirm; worth a human look, not an
                     automatic verdict.
    """
    events_sorted = sorted(events, key=lambda e: parse_ts(e["timestamp"]))

    logins_by_user = {}
    logins_by_ip = {}
    for e in events_sorted:
        if e["event_type"] == "login":
            t = parse_ts(e["timestamp"])
            if e.get("user"):
                logins_by_user.setdefault(e["user"], []).append(t)
            logins_by_ip.setdefault(e["source_ip"], []).append(t)

    findings = []
    for e in events_sorted:
        if e["event_type"] != "admin_token_mint":
            continue
        ip = e["source_ip"]
        user = e.get("user")
        mint_time = parse_ts(e["timestamp"])

        prior_logins = [t for t in logins_by_ip.get(ip, []) if t < mint_time]
        if user:
            prior_logins += [
                t for t in logins_by_user.get(user, []) if t < mint_time
            ]

        if prior_logins:
            findings.append(
                {
                    "source_ip": ip,
                    "user": user,
                    "mint_time": e["timestamp"],
                    "verdict": "SUPPRESSED",
                    "reason": (
                        "prior authenticated session (by user or IP) at "
                        f"{max(prior_logins).isoformat()}"
                    ),
                }
            )
            continue

        window_end = mint_time + timedelta(minutes=correlation_window_minutes)
        followups = [
            ev
            for ev in events_sorted
            if ev["source_ip"] == ip
            and ev["event_type"] in ("enumeration", "account_creation")
            and mint_time <= parse_ts(ev["timestamp"]) <= window_end
        ]

        verdict = (
            "CONFIRMED"
            if len(followups) >= 2
            else "SUSPICIOUS (no prior session, insufficient follow-up burst)"
        )
        findings.append(
            {
                "source_ip": ip,
                "user": user,
                "mint_time": e["timestamp"],
                "verdict": verdict,
                "evidence": [
                    f"{ev['event_type']} at {ev['timestamp']}" for ev in followups
                ],
            }
        )

    return findings


if __name__ == "__main__":
    import json

    # Scenario 1: legit CI service account -- authenticates, then mints
    # a token for its own automation. Should be SUPPRESSED.
    scenario_legit_ci = [
        {"timestamp": "2026-09-10T02:00:00", "source_ip": "10.0.5.20",
         "event_type": "login", "user": "ci-service-account"},
        {"timestamp": "2026-09-10T02:00:05", "source_ip": "10.0.5.20",
         "event_type": "admin_token_mint", "user": "ci-service-account"},
    ]

    # Scenario 2: legit human admin, normal usage after a single mint.
    # Should be SUPPRESSED.
    scenario_legit_human = [
        {"timestamp": "2026-09-10T09:15:00", "source_ip": "192.168.1.44",
         "event_type": "login", "user": "jsmith"},
        {"timestamp": "2026-09-10T09:20:00", "source_ip": "192.168.1.44",
         "event_type": "admin_token_mint", "user": "jsmith"},
        {"timestamp": "2026-09-10T09:25:00", "source_ip": "192.168.1.44",
         "event_type": "enumeration", "user": "jsmith"},
    ]

    # Scenario 3: the malicious phantom-join-key sequence per Wiz/HEARTH
    # reporting -- no login, immediate mint, immediate enumeration +
    # rogue account creation. Should be CONFIRMED.
    scenario_malicious = [
        {"timestamp": "2026-09-10T03:41:00", "source_ip": "185.220.101.7",
         "event_type": "admin_token_mint", "user": None},
        {"timestamp": "2026-09-10T03:41:45", "source_ip": "185.220.101.7",
         "event_type": "enumeration", "user": None},
        {"timestamp": "2026-09-10T03:42:30", "source_ip": "185.220.101.7",
         "event_type": "account_creation", "user": "svc_a1b2c3d4"},
    ]

    # Edge case A: attacker with only 1 follow-up event -- should be
    # SUSPICIOUS, not CONFIRMED (tests the >=2 threshold doesn't over-fire).
    edge_a = [
        {"timestamp": "2026-09-11T04:00:00", "source_ip": "203.0.113.5",
         "event_type": "admin_token_mint", "user": None},
        {"timestamp": "2026-09-11T04:00:30", "source_ip": "203.0.113.5",
         "event_type": "enumeration", "user": None},
    ]

    # Edge case B: follow-up events fall outside the correlation window
    # (10 min later vs a 3 min window) -- should NOT confirm.
    edge_b = [
        {"timestamp": "2026-09-11T05:00:00", "source_ip": "198.51.100.9",
         "event_type": "admin_token_mint", "user": None},
        {"timestamp": "2026-09-11T05:10:00", "source_ip": "198.51.100.9",
         "event_type": "enumeration", "user": None},
        {"timestamp": "2026-09-11T05:11:00", "source_ip": "198.51.100.9",
         "event_type": "account_creation", "user": "x"},
    ]

    # Edge case C: a REAL false-positive risk found by testing v1 of this
    # logic -- a legit admin logs in from one IP, but the token mint
    # happens from a different IP (NAT / load balancer between login and
    # API call). v1 (pure IP-keyed correlation) incorrectly flagged this
    # as SUSPICIOUS. Fixed in this version by also correlating on user
    # identity when available. Should be SUPPRESSED.
    edge_c = [
        {"timestamp": "2026-09-11T06:00:00", "source_ip": "10.1.1.1",
         "event_type": "login", "user": "admin2"},
        {"timestamp": "2026-09-11T06:00:10", "source_ip": "10.1.1.2",
         "event_type": "admin_token_mint", "user": "admin2"},
    ]

    all_events = (
        scenario_legit_ci
        + scenario_legit_human
        + scenario_malicious
        + edge_a
        + edge_b
        + edge_c
    )

    for finding in detect_h294(all_events, correlation_window_minutes=3):
        print(json.dumps(finding, indent=2))
