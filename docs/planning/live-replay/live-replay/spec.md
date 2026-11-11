# Aspect Spec — Live Proof Replay

- **Feature:** `live-replay`
- **Aspect:** `live-replay`
- **PRD:** `../prd.md`
- **Status:** Implemented and merged (2026-11-11)

## Problem slice

`pry replay` verifies a signed read-only proof and re-sends its GET against the P1-verified
live target. Status match only; no new verdict or proof.

## In scope

- `replay.py` (verify shape, token, same-origin, GET-only, status compare).
- CLI `replay FILE [--fingerprint] [--token/--token-file] [--json]`.
- Header allowlist, no redirects, 5s timeout, 4 KiB cap.
- Loopback tests; docs/ETHICS.

## Out of scope

- Local/sandbox replay, write replay, probe-specific re-evaluation, new proof signing.
- IDOR discovery, provider DB rules, live SSRF, hosted reports.

## Acceptance criteria

PRD AT1–AT9. Every AT maps to a test in the plan.

## Dependencies and sequencing

- P1, P5, P6, and the read-only probes are merged.
- No new dependencies; Python 3.9; default suite offline except loopback.
