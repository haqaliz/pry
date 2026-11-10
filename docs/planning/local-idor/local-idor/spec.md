# Aspect Spec — Configured Local IDOR

- **Feature:** `local-idor`
- **Aspect:** `local-idor`
- **PRD:** `../prd.md`
- **Status:** Approved (2026-11-11)

## Problem slice

Run the live IDOR check inside the local sandbox with a 0600 config mounted read-only. Three
GETs, both controls, redacted result, signed EXPOSED. No discovery, no live changes.

## In scope

- Sidecar `idor` mode and shared probe core.
- Config mount in `start_sidecar`; temp 0600 config; cleanup.
- `scan_local`/CLI local `--idor-config`; signed/report.
- Tests; Docker fixture; docs.

## Out of scope

- IDOR discovery, non-configured sweeps, live changes, DB rules, level 2/writes, hosted reports.

## Acceptance criteria

PRD AT1–AT10. Every AT maps to a test in the plan.

## Dependencies and sequencing

- P1–P4, P5, P6, ETHICS.md are merged.
- No new dependencies; Python 3.9; default suite offline.
