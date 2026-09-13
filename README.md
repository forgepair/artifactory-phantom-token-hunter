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

## The CLI tool

`src/phantom_hunter/` is a real, installable CLI (`phantom-hunter`, via
`[project.scripts]`) that runs the H294 correlation against actual JFrog log
files instead of the synthetic single-event-stream model in `detector.py`.

**Built around JFrog's own documented log formats, researched before writing
any parser** (closing the exact gap the original proof-of-mechanism flagged
as unverified):

- **Audit Trail Log** (`docs.jfrog.com/administration/docs/audit-trail-log`)
  -- pipe-delimited, 9 fields (`Date|Trace ID|User IP|User|Logged
  Principal|Entity Name|Event Type|Event|Data Changed`). This is the real
  source of token-*creation* events: `Event == TKN`, `Event Type == C`.
- **Access Log** (`docs.jfrog.com/administration/docs/access-log`) --
  bracketed free-text (`Timestamp [Trace Id] [Response Action] ... for
  User/IP`). This is the real source of `LOGIN` events, used for "prior
  authenticated session." JFrog's own docs are internally inconsistent about
  the timestamp format (the field spec claims RFC-3339; the docs' own sample
  line uses comma-millis, no `T`/`Z`) -- the parser accepts both rather than
  silently dropping real lines in one of the two shapes.
- **router-request.log** -- pipe-delimited, 11 fields (`Timestamp|Trace
  ID|Remote IP|Username|Method|URL|Status|Req Len|Resp Len|Duration|User
  Agent`). This is the router-fronted API traffic log (distinct from the
  per-repository `artifactory-request.log`, which logs a *repository name*
  in that column instead of an IP) -- it's the one that actually captures
  calls to `/access/api/v1/tokens` and `/api/security/*`, so it's the real
  source for both the mint call itself and the enumeration burst.

**One confirmed, honest gap**: JFrog's docs confirm the Audit Trail Log
records token creation but never publish a sample `Data Changed` payload for
it, so "is this token admin-scoped" (`models.py`'s `looks_admin_scoped`) is
a documented-but-unverified heuristic (substring match on the scope string),
not a confirmed field mapping.

**A CI-identity allowlist** (`baseline.py`) closes the other gap the
original proof-of-mechanism left open: H294's own author-named top
false-positive mitigation ("baseline [CI service principals] and suppress
them explicitly") is now a real mechanism (`--allowlist allowlist.json`),
not just an implicit "has this identity ever logged in before" heuristic.

**A real bug found by testing, not review**: the login-line regex's IP
character class greedily swallowed the log line's trailing period
(`192.168.1.44.` parsed as IP `192.168.1.44.`, not `192.168.1.44`) --
caught by two failing tests in `tests/test_parsers.py`, fixed with an
explicit `.rstrip(".")`.

**Verified end-to-end as a real subprocess**, not just via in-process test
calls -- `python -m phantom_hunter.cli --audit-log ... --access-log ...
--request-log ... --allowlist ...` against real-shaped log files on disk
produces correct JSON verdicts and a real exit code (0/1/2 by highest
severity found, for use in a pipeline).

37/37 tests passing (`python -m pytest tests/ -v`): the original 9 plus 28
new tests across parsers (anchored to JFrog's own real documented request-log
sample line), the enumeration classifier (including the important negative
case -- the mint's own `/access/api/v1/tokens` call must never count as its
own enumeration evidence), the allowlist, the full correlation engine, and
two CLI end-to-end tests.

### Usage

```
python -m pip install -e .
phantom-hunter \
  --audit-log /path/to/artifactory-audit-trail.log \
  --access-log /path/to/artifactory-access.log \
  --request-log /path/to/router-request.log \
  --allowlist ./ci-allowlist.json \
  --window-minutes 3
```

`ci-allowlist.json` shape:

```json
[{"user": "ci-service-account", "ip_prefix": "10.0.5."}]
```

## What's still needed before this is a real tool

- **Still not tested against a real, captured Artifactory log file.** The
  parsers are now built against JFrog's own documented field grammar
  (including one real sample line for the request log), but every log line
  in this project's tests is still hand-constructed to match that
  documentation -- none has been cross-checked against actual output from a
  running Artifactory instance, which could easily surface format drift the
  docs don't mention.
- **Admin-scope detection is a documented-but-unverified heuristic**, not a
  confirmed field mapping -- see "The CLI tool" above. A real deployment
  needs a live Audit Trail Log sample for a token-creation event to replace
  the substring-match heuristic with an actual field.
- **CI-service baselining now exists as a mechanism** (`--allowlist`), but
  ships with no real seed data -- a real deployment has to populate its own
  allowlist from its own known service accounts; nothing here discovers them
  automatically.
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
