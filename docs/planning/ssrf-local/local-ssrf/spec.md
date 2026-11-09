# Aspect Spec — Local SSRF (Level 1)

- **Feature:** `ssrf-local`
- **Aspect:** `local-ssrf`
- **PRD:** `../prd.md`
- **Status:** Implemented and merged (2026-11-10)

## Problem slice

Prove a declared local app fetch endpoint actually fetches a Pry callback URL. Level 1,
read-only, explicitly confirmed; no live SSRF, no rate-limit, no writes.

## In scope

- Callback sidecar on the sandbox internal network, alias `pry-callback`, port 9000, hit log.
- `ssrf_probe.py` GET query injection + hit polling.
- `SsrfConfig` validation and result mapping.
- `scan_local(level=1, ssrf_config=...)`; CLI `--level 1 --confirm --ssrf-*`.
- Signed proof/report/corpus; offline tests; Docker fixture; docs.

## Out of scope

- Live SSRF/public callback, rate-limit, Level 2/writes.
- POST/body/header injection, discovery, auth, DB rules, hosted reports.

## Acceptance criteria

PRD AT1–AT10. Every AT maps to a test in the plan.

## Dependencies and sequencing

- P1–P3, P5, P6, live scans, IDOR, ETHICS.md are merged.
- No new dependencies; Python 3.9; default suite offline.
