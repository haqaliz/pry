# Aspect Spec — Provider Database Rules

- **Feature:** `provider-db`
- **Aspect:** `provider-db`
- **PRD:** `../prd.md`
- **Status:** Approved (2026-11-11)

## Problem slice

A 0600 config names a Firebase RTDB or Supabase REST project, a marker the owner placed, and
one data path. Pry reads the marker unauthenticated, then the data path. Non-empty JSON without
credentials is EXPOSED, signed. Marker failure exits before the data request.

## In scope

- `database_rules.py`: config, validation, marker/data probe.
- Firebase RTDB and Supabase REST; `apikey` redaction; HTTPS-only except loopback.
- `pry database` CLI, proof/corpus/report, loopback tests.
- Docs/ETHICS.

## Out of scope

- Firestore/other providers, rule parsing, writes, discovery, bulk dumps.
- IDOR discovery, live SSRF, hosted reports.

## Acceptance criteria

PRD AT1–AT9. Every AT maps to a test in the plan.

## Dependencies and sequencing

- P1, P5, P6, live scan/proof/replay are merged.
- No new dependencies; Python 3.9; default suite offline except loopback.
