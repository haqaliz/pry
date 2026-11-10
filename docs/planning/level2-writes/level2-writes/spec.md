# Aspect Spec — Local Level 2 Write Confirmation

- **Feature:** `level2-writes`
- **Aspect:** `level2-writes`
- **PRD:** `../prd.md`
- **Status:** Implemented and merged (2026-11-11)

## Problem slice

Local-only declared unauthenticated write, followed by a verification read. `EXPOSED` only when
both succeed and the unique marker is present. Config 0600, temp 0600, read-only mount, cleanup.
Live writes rejected before any request.

## In scope

- `write.py` config/validation/parser; sidecar `probe_write` and `write` mode.
- Docker config mount; temp config lifecycle; client `run_write`.
- `scan_local(..., write_config=None)`.
- CLI `--level 2 --confirm --write-config FILE`; live rejection.
- Signed proof/report; Docker fixture; docs.

## Out of scope

- Live writes, DELETE, uploads, auth, multi-step workflows.
- IDOR discovery, provider DB rules, live SSRF, hosted reports.

## Acceptance criteria

PRD AT1–AT10. Every AT maps to a test in the plan.

## Dependencies and sequencing

- P1–P4, P5, P6, ETHICS.md, local IDOR, header observations, database files, live rate-limit
  are merged.
- No new dependencies; Python 3.9; default suite offline.
