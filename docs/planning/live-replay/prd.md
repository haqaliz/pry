# PRD — Live Proof Replay (P5 remainder)

- **Status:** Merged to `master` (2026-11-11). Live read-only proof replay implemented;
  local/write replay and key distribution remain deferred.
- **Owner:** aliz
- **Slug:** `live-replay`
- **Capability:** P5 — live read-only proof replay

## Problem Statement

Pry signs each `EXPOSED` finding so it can be verified offline. The roadmap also promises live
replay: re-sending the saved request against the owner's target to show it still reproduces.
Without replay, a proof is a historical record only. The safe slice is a read-only GET with no
credentials, a fresh P1 check, and a status comparison.

## Goals & Success Metrics

1. `pry replay BUNDLE --token TOKEN` verifies the bundle and the token before any request.
2. Re-sends the recorded GET with no auth/cookie, no redirects, 5s timeout, 4 KiB cap.
3. `MATCH` when the replay status equals the recorded status; `MISMATCH` otherwise;
   `UNVERIFIED` on transport.
4. Local bundles, non-GET findings, and foreign request URLs exit 2 before any request.
5. No new proof, no verdict, no token storage; docs say status-only.

## Requirements

| ID | Requirement |
|---|---|
| M1 | `pry replay FILE [--fingerprint] [--token/--token-file] [--json]`. |
| M2 | Verify the bundle signature and optional fingerprint; reject non-live targets and non-GET findings. |
| M3 | Validate a P1 token for the bundle target origin before any request. |
| M4 | Require the recorded request URL to be same-origin; send only `User-Agent`/`Accept`. |
| M5 | No redirects, 5s timeout, 4 KiB cap; compare only statuses. |
| M6 | Exit 0 match, 1 mismatch, 2 invalid/unverified; JSON output. |
| M7 | Tests: loopback match/mismatch/transport, invalid, non-live, non-GET, wrong token, headers. |
| M8 | Docs: replay is status-only, not a new finding; no secure. |

## Technical Considerations

- New `src/pry/probe/replay.py` with `ReplayError`, `replay_bundle(payload, token, fetch=None)`.
- Reuse `load_bundle`/`verify_bundle`, `TokenSigner`, `normalize_target`, `urllib_fetch`
  (no redirects, body cap).
- The finding request headers are lowercase; filter to `user-agent`/`accept`.
- CLI `cmd_replay`; `--json`; no run directory.
- No new dependencies; Python 3.9.

## Risks

| Risk | Severity | Mitigation |
|---|---|---|
| **Replaying a write or credentialed request.** | High/High | GET-only, redacted-header allowlist, no auth/cookie. |
| **Scanning a target without ownership.** | High/High | Fresh P1 token validation before any request. |
| **A status match read as "still vulnerable".** | Med/High | Status-only wording; no verdict/proof; docs. |
| **Redirect to another origin.** | Med/Med | No redirects; same-origin request URL required. |

**Hard question:** a matching status does not prove the same data came back. The output says
"status match only"; it is a reproducibility check, not a new finding.

## Out of Scope

- Local/sandbox replay, write replay, probe-specific re-evaluation, new proof signing.
- IDOR discovery, provider DB rules, live SSRF, hosted reports.

## Acceptance Tests

| ID | Test | Expected |
|---|---|---|
| AT1 | Valid live GET proof, same status | MATCH, exit 0 |
| AT2 | Different status | MISMATCH, exit 1 |
| AT3 | Transport failure | UNVERIFIED, exit 2 |
| AT4 | Invalid bundle/fingerprint | exit 2, no request |
| AT5 | Local/non-GET/foreign URL | exit 2, no request |
| AT6 | Missing/wrong token | exit 2, no request |
| AT7 | Recorded auth/cookie headers | not sent |
| AT8 | JSON output | status + statuses |
| AT9 | Docs | status-only, no secure |

## Self-Critique

- 🟡 **Status-only is weak.** Say so plainly; do not call a match `EXPOSED`.
- 🟡 **A live GET still carries risk.** The P1 token and no-credential rule are the guardrails.
- 🟢 **It makes every read-only proof checkable without a new scan.**
