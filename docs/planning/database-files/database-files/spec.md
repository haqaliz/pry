# Aspect Spec — Exposed Database Files

- **Feature:** `database-files`
- **Aspect:** `database-files`
- **PRD:** `../prd.md`
- **Status:** Implemented and merged (2026-11-11)

## Problem slice

Four fixed database paths get one unauthenticated GET each. A same-origin 2xx response with a
SQLite header or SQL-dump signature is an `EXPOSED` finding with a signed proof. The stored
body is a signature excerpt only. Always-on level 0, local and live.

## In scope

- `probe_database` and the `database` probe in the sidecar.
- Local `PROBE_ORDER` and live probe list.
- Signed proof, report, CLI/JSON, corpus via the shared path.
- Tests; Docker fixture with a served SQL dump; docs.

## Out of scope

- Firebase/Supabase open-rule checks and third-party DB ownership.
- Discovery, credentials, bulk download, SQL injection.
- Header policy analysis, live SSRF, live rate-limit, Level 2, hosted reports.

## Acceptance criteria

PRD AT1–AT9. Every AT maps to a test in the plan.

## Dependencies and sequencing

- P1–P4, P5, P6, ETHICS.md, local IDOR, header observations are merged.
- No new dependencies; Python 3.9; default suite offline.
