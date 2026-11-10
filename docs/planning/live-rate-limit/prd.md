# PRD — Live Rate-Limit Observation (P4 remainder)

- **Status:** Approved on standing instruction (2026-11-11)
- **Owner:** aliz
- **Slug:** `live-rate-limit`
- **Capability:** P4 — bounded live rate-limit observation

## Problem Statement

Pry can observe throttling locally, but a live URL rejects every level 1 check. The owner of a
live app may want to know whether a declared endpoint throttles repeated requests. That is a
hardening observation, not a reproduced exploit, and it carries real load and lockout risk. The
honest version is small, bounded, explicit, and stoppable.

## Goals & Success Metrics

1. Live level 1 runs only with `--confirm` and a declared endpoint.
2. At most 5 GETs, 0.5s apart, no auth, stop on the first 429/503/`Retry-After`.
3. `OBSERVED`/`THROTTLED`/`UNVERIFIED` observation; no proof, verdict, or exit change.
4. Missing confirmation, endpoint, or an over-cap count exits 2 before any request.
5. Live SSRF stays rejected; P1 is validated first.

## Requirements

| ID | Requirement |
|---|---|
| M1 | Live `--level 1` requires `--confirm` and `--rate-limit-endpoint PATH`; path-only, no query/fragment. |
| M2 | Live count 1–5, default 5; 0.5s spacing; stop on 429/503/`Retry-After`. |
| M3 | `probe_rate_limit` is reused in-process; the request count and statuses are recorded. |
| M4 | The observation is appended to `observations`, never results; no proof, no signature. |
| M5 | The P1 token is validated before any request. |
| M6 | CLI/JSON/report show the observation; exit code depends only on `EXPOSED` results. |
| M7 | Tests: validation, live scan, CLI gate, throttling stop, no proof, exit neutral. |
| M8 | Docs/ETHICS: explicit confirmation, cap, spacing, stop, risk, no secure. |

## Technical Considerations

- Extend `validate_rate_limit(endpoint, count, max_count=RATE_LIMIT_MAX_COUNT)`; live passes 5.
- Add `LIVE_RATE_LIMIT_MAX_COUNT = 5`, `LIVE_RATE_LIMIT_DEFAULT_COUNT = 5`,
  `LIVE_RATE_LIMIT_SPACING = 0.5`.
- `probe_rate_limit(..., spacing=RATE_LIMIT_SPACING)`; live passes 0.5.
- `scan_live(..., rate_limit_config=None)` validates the cap and appends the observation.
- CLI `_scan_target_url` allows live level 1 only for rate-limit; rejects SSRF flags.
- No new dependencies; no Docker; no credentials.

## Risks

| Risk | Severity | Mitigation |
|---|---|---|
| **Account lockout/WAF from a live sample.** | Med/High | Explicit `--confirm`, max 5, 0.5s spacing, stop on first throttle, owner-declared endpoint. |
| **Load on a shared target.** | Med/Med | The P1 token is the owner's authorization; docs say stop if it is shared/production. |
| **A missing limit read as `EXPOSED`.** | High/High | Observation only; never a verdict or proof. |
| **Accidental default run.** | High/High | Level 1 + confirm + endpoint required; no flag → no check. |
| **SSRF accidentally enabled live.** | Med/High | Live SSRF flags exit 2 before any request. |

**Hard question:** five requests can still trigger a lockout on an auth endpoint. The owner
declares the path and confirms; the docs say not to point it at login or account-recovery paths.

## Out of Scope

- Live SSRF, Level 2 writes, IDOR discovery, provider DB rules, hosted reports.
- Load testing, concurrency, credential use.

## Acceptance Tests

| ID | Test | Expected |
|---|---|---|
| AT1 | Live level 1 + confirm + endpoint | one observation |
| AT2 | 429/503/Retry-After | THROTTLED, stop |
| AT3 | 200s | OBSERVED with count/statuses |
| AT4 | count 6 | exit 2, no request |
| AT5 | no confirm / no endpoint | exit 2, no request |
| AT6 | SSRF flags on URL | exit 2, no request |
| AT7 | Observation | no proof/verdict; exit unchanged |
| AT8 | Docs | cap, spacing, stop, risk, no secure |

## Self-Critique

- 🟡 **This reverses a previous deferral.** The cap, spacing, stop, and explicit confirmation
  are the reason it is acceptable now; the docs say so plainly.
- 🟡 **Five requests is still a sample.** A missing limit is not a finding.
- 🟢 **No auth, no writes, no proof, no verdict.**
