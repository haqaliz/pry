# Aspect Spec — Live Rate-Limit Observation

- **Feature:** `live-rate-limit`
- **Aspect:** `live-rate-limit`
- **PRD:** `../prd.md`
- **Status:** Implemented and merged (2026-11-11)

## Problem slice

Allow a bounded live rate-limit sample at level 1 with explicit confirmation: max 5 GETs,
0.5s spacing, stop on the first throttle. Unsigned observation, no verdict, no proof.

## In scope

- Live cap/default/spacing constants and validation.
- `probe_rate_limit` spacing parameter; `scan_live` observation.
- CLI live level 1 gate; live SSRF rejection; tests; docs/ETHICS.

## Out of scope

- Live SSRF, Level 2 writes, IDOR discovery, provider DB rules, hosted reports.
- Load testing, concurrency, credentials.

## Acceptance criteria

PRD AT1–AT8. Every AT maps to a test in the plan.

## Dependencies and sequencing

- P1–P4, P5, P6, ETHICS.md, local IDOR, header observations, database files are merged.
- No new dependencies; Python 3.9; default suite offline.
