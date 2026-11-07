# Aspect Spec — Configured IDOR Probe

- **Feature:** `idor-live`
- **Aspect:** `configured-idor`
- **PRD:** `../prd.md`
- **Status:** Approved on standing instruction (2026-11-08)

## Problem slice

Add a live-only, configured IDOR check: two identities, two object paths, three GETs, a
control gate, and credential redaction. No discovery, no local IDOR.

## In scope

- `IdorConfig` loader with 0600/header/path validation.
- `probe_idor` with controls and verdicts.
- `scan_live`/CLI `--idor-config`; signed proof/report.
- Offline tests; loopback integration; docs.

## Out of scope

- Local IDOR, discovery, DB rules, P4, writes, hosted reports.

## Acceptance criteria

PRD AT1–AT10. Every AT maps to a test in the plan.

## Dependencies and sequencing

- P1, live read-only path, P5, P6, ETHICS.md are merged.
- No new dependencies; Python 3.9; default suite offline.
