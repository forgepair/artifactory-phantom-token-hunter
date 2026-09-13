# artifactory-phantom-token-hunter

A retro-hunting tool for JFrog Artifactory that detects admin-scoped access
tokens minted **without a prior authenticated session** -- the attacker
signature behind CVE-2026-82329's "phantom join key" exploitation -- followed
by a correlated burst of security-model enumeration.

## Why this exists

CVE-2026-82329 (CVSS 9.8, disclosed 2026-08-28) lets an unauthenticated
attacker with network access mint a fully-privileged admin token against
self-hosted JFrog Artifactory instances that received a "phantom" default
join key. Confirmed exploitation moved from disclosure to observed
in-the-wild admin-token-minting in **four days** (watchTowr honeypot
telemetry). Artifactory is the trust anchor for CI/CD build and release
pipelines -- admin control converts an intrusion into a software-supply-chain
substitution attack.

**Patching does not undo this.** Upgrading closes the door but does not evict
admin tokens minted before the patch. Every patched-but-previously-exposed
instance needs a retroactive hunt, not just a version check.

## The hypothesis this operationalizes

[`THORCollective/HEARTH` H294](https://github.com/THORCollective/HEARTH/blob/main/Flames/H294.md)
-- "Artifactory Admin Token Minting Without Prior Authenticated Session" --
submitted by practitioner Joshua Strickland. Pulled and read directly (not
summarized secondhand) via `gh api`, and independently re-verified against
this repo's own copy of the correlation logic: the same author, tactics
(T1190, T1195.002, T1098.001, T1087, T1552, T1059), false-positive guidance,
and required data sources quoted in this project trace back to that document
exactly as written.

Core detection logic (the hypothesis's own words): filter Artifactory
Access-service logs for successful token-creation requests to
`/access/api/v1/tokens` where the requesting source IP has no successful
interactive login or existing session in the preceding lookback window,
especially where token `scope` contains `applied-permissions/admin`.
Correlate with a burst of hits to `/api/security/users`,
`/api/security/groups`, `/api/security/permissions`, and federation/
credential-set endpoints within minutes of the mint.

## No existing implementation

Independently searched GitHub repo and code search for any tool
operationalizing this correlation (2026-09-13): zero defensive
implementations found. The only hits are offensive exploit PoCs against the
CVE itself (`dinosn/cve-2026-82329-jfrog-artifactory`,
`ynsmroztas/CVE-2026-82329-JFrog-Artifactory-Auth-Bypass`, and others) and
generic CVE-aggregator/mirror bots that just republish the CVE description --
nothing that implements the log correlation the hypothesis describes. The
only automated capability in this space is reported to be a proprietary paid
Wiz Defend feature.

## Proof of mechanism -- built, run, and tested

`src/detector.py` implements the H294 correlation logic against synthetic
Artifactory-log-shaped events (timestamp, source IP, user, event type).

`tests/test_detector.py` -- **9 real, asserted pytest tests** (not just
printed output): the 6 original scenarios plus 3 more added while turning
this from a proof-of-mechanism script into an actual test suite:

1. Legit CI service account (login, then self-mint) -> `SUPPRESSED`
2. Legit human admin (login, mint, light browsing) -> `SUPPRESSED`
3. The real malicious sequence (no login, immediate mint, immediate
   enumeration + rogue account creation) -> `CONFIRMED`
4. A single follow-up event only (not a full burst) -> `SUSPICIOUS`, not a
   forced `CONFIRMED` -- the `>=2 events` threshold doesn't over-fire
5. Follow-up events outside the correlation window -> stays `SUSPICIOUS`
6. **A real false-positive mode found by testing, not assumed**: a
   legitimate admin logs in from one IP, but NAT/load-balancing causes the
   token-mint API call to arrive from a *different* IP. A first version of
   this logic (pure IP-keyed correlation) incorrectly flagged this as
   suspicious; fixed by also correlating on user identity when available.
   This exact concern is independently called out in H294's own
   author-written false-positive notes, confirming the stress-testing caught
   a real, previously-recognized risk.
7. **New**: a login that happens *after* the mint does not retroactively
   suppress it -- only a prior session counts. Confirms the code isn't
   suppressing on "any login exists anywhere for this identity."
8. **New**: a follow-up event landing exactly on the correlation window's
   boundary still counts (`mint_time <= t <= window_end`, inclusive).
9. **New**: no admin-token-mint events in the input produces no findings,
   not an error.

All 9 pass (`python -m pytest tests/ -v`).

## What's still needed before this is a real tool

- **Not yet tested against a real Artifactory access log.** All testing so
  far is against synthetic data shaped like the documented log fields -- the
  actual field names/format of JFrog's real Access service logs and audit
  trail have not been pulled from JFrog's own documentation and cross-checked
  against this script's assumptions.
- **Enumeration/account-creation event detection is not yet implemented** --
  the proof-of-mechanism assumes these events are already classified and fed
  in; a real tool needs to parse raw Artifactory/reverse-proxy logs and
  classify hits to `/api/security/users` etc. as "enumeration" itself.
- **CI-service baselining/suppression** (the author's own top false-positive
  mitigation) is not yet built -- this needs an allowlist mechanism for
  known-stable service identities, not just the "has any prior login" check
  currently implemented.
- **Demand remains unconfirmed.** No named practitioner has been found
  publicly asking for this exact tool to exist -- the case for building it
  rests on the hypothesis's own severity framing and the absence of any
  existing implementation, not a direct request.

## Product shape (not yet built beyond the proof)

A CLI tool ingesting real JFrog Artifactory Access-service logs + reverse-proxy
logs, implementing the full H294 correlation (token mint classification,
endpoint-based enumeration detection, CI-identity baselining, the
time-windowed burst correlation proven here) and emitting
SUPPRESSED/SUSPICIOUS/CONFIRMED verdicts per the hypothesis's own triage
fields (source IP, token subject, token scope, token expiry, user agent,
request ID). Positioned as a companion to (not a replacement for) existing
vulnerability scanners (nuclei, Qualys) that detect the unpatched CVE -- this
tool is for *retro-hunting already-compromised* instances, patched or not.

## License

MIT
