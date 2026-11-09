# Aspect Spec — Local Rate-Limit Observation

- **Feature:** `rate-limit`
- **Aspect:** `local-rate-limit`
- **PRD:** `../prd.md`
- **Status:** Approved (2026-11-10)

## Problem slice

Run a bounded series of GETs against a declared local endpoint and record whether the app
throttles. This is a separate hardening observation, not a verdict and not a signed proof.

## In scope

- `probe_rate_limit` in the sidecar; statuses OBSERVED/THROTTLED/UNVERIFIED.
- `RateLimitConfig` validation; count 1–20; path-only endpoint; no live.
- `ScanResult`/`ScanOutcome` observations; `results.json`; CLI/JSON; report section.
- Level 1 + `--confirm`; at least one of SSRF/rate-limit.
- Tests; Docker fixture; docs.

## Out of scope

- Treating missing rate limiting as `EXPOSED`; live rate-limit; Level 2/writes; auth.
- Proof bundles for observations; hosted reports.

## Acceptance criteria

PRD AT1–AT10. Every AT maps to a test in the plan.

## Dependencies and sequencing

- P1–P4 SSRF, P5, P6, ETHICS.md are merged.
- No new dependencies; Python 3.9; default suite offline.
