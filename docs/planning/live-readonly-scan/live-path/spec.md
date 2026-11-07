# Aspect Spec — Live Read-Only Path

- **Feature:** `live-readonly-scan`
- **Aspect:** `live-path`
- **PRD:** `../prd.md`
- **Status:** Approved on standing instruction (2026-11-08)

## Problem slice

Run the existing read-only probes against a live URL the user has proven they own. P1
validates before any request; results are signed and reportable. No sandbox, no Docker, no
writes.

## In scope

- `scan_live` + live snapshot + shared finalization.
- CLI URL path; `--report`, `--json`, `--endpoint`, `--out`.
- Report host/ownership proof.
- Offline fake-probe tests; loopback HTTP integration; docs.

## Out of scope

- Live writes/levels 1–2/P4, IDOR/DB, discovery, auth, hosted reports.

## Acceptance criteria

PRD AT1–AT10. Every AT maps to a test in the plan.

## Dependencies and sequencing

- P1–P3, P5, P6, ETHICS.md are merged.
- No new dependencies; Python 3.9; default suite offline.
