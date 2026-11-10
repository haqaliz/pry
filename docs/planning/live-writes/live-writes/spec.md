# Aspect Spec — Live Level 2 Write Confirmation

- **Feature:** `live-writes`
- **Aspect:** `live-writes`
- **PRD:** `../prd.md`
- **Status:** Approved (2026-11-11)

## Problem slice

Allow one declared live write only with `--level 2`, `--confirm`, `--confirm-live-write`, a
P1 token, and a 0600 write config. Reuse the local write probe/marker verification; run it in
process after the read-only probes. Signed EXPOSED; no rollback.

## In scope

- `scan_live(..., write_config=None)`.
- CLI `--confirm-live-write`; live level 2 gate; live rate-limit remains available.
- Loopback integration; tests; docs/ETHICS warning.

## Out of scope

- DELETE, uploads, auth, multi-step workflows, rollback.
- IDOR discovery, provider DB rules, live SSRF, hosted reports.

## Acceptance criteria

PRD AT1–AT9. Every AT maps to a test in the plan.

## Dependencies and sequencing

- P1–P4, P5, P6, ETHICS.md, local Level 2 writes are merged.
- No new dependencies; Python 3.9; default suite offline.
