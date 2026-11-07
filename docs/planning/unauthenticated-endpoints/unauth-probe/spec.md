# Aspect Spec — Unauthenticated Endpoint Probe

- **Feature:** `unauthenticated-endpoints`
- **Aspect:** `unauth-probe`
- **PRD:** `../prd.md`
- **Status:** Implemented and merged (2026-11-07)

## Problem slice

Add one read-only probe to the existing sidecar: GET a declared-protected path with no
credentials and decide `EXPOSED` only from a 2xx JSON response. Wire it through the client,
scan, and CLI.

## In scope

- `--endpoint` repeatable on local `pry scan`.
- Path-only validation (host and sidecar).
- Sidecar `unauth` probe; one result per endpoint.
- Client/scan plumbing; `results.json`; JSON/human output; exit codes.
- Offline tests; opt-in Docker tests; docs truth.

## Out of scope

- Discovery, IDOR, DB rules, header-only findings, live URL, levels 1–2.

## Acceptance criteria

PRD AT1–AT10. Every AT maps to a test in the plan.

## Dependencies and sequencing

- P1, P2, P3 first slice, ETHICS.md are merged.
- No new dependencies; Python 3.9.
- The default three-probe scan is unchanged when no endpoint is supplied.
