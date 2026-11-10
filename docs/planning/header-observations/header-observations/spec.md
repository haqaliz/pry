# Aspect Spec — Response Header Observations

- **Feature:** `header-observations`
- **Aspect:** `header-observations`
- **PRD:** `../prd.md`
- **Status:** Implemented and merged (2026-11-11)

## Problem slice

Opt-in `--headers` check on `/`: one GET, recommended response headers, missing/present as an
unsigned observation. Local and live; never a verdict or proof.

## In scope

- `probe_headers` + parser; local sidecar and live in-process.
- `--headers` on local/live; observations in results/CLI/report.
- Tests; Docker fixtures; docs.

## Out of scope

- Missing headers as `EXPOSED`, grading, CSP parsing, cookie/TLS checks, hosted reports.

## Acceptance criteria

PRD AT1–AT8. Every AT maps to a test in the plan.

## Dependencies and sequencing

- P1–P4, P5, P6, ETHICS.md are merged.
- No new dependencies; one GET; default suite offline.
