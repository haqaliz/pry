# Aspect Spec — Live SSRF with a User Callback

- **Feature:** `live-ssrf`
- **Aspect:** `live-ssrf`
- **PRD:** `../prd.md`
- **Status:** Approved (2026-11-11)

## Problem slice

Live level 1 SSRF with a user-supplied callback base URL: one declared fetch with a per-run
nonce, then up to three polls. A callback 200 is EXPOSED; no hit is NOT_REPRODUCED. Signed proof
with both pairs. Local SSRF unchanged.

## In scope

- `live_ssrf.py`: config/validation/probe.
- `scan_live(..., ssrf_config=None)`; CLI `--ssrf-callback-url`; live gate; local rejection.
- Proof/report; loopback end-to-end; docs/ETHICS.

## Out of scope

- Pry-hosted callbacks/tunnels, internal port scanning, credential use.
- IDOR discovery, hosted reports.

## Acceptance criteria

PRD AT1–AT10. Every AT maps to a test in the plan.

## Dependencies and sequencing

- P1, P4, P5, P6, live scan/proof/replay/provider DB are merged.
- No new dependencies; Python 3.9; default suite offline except loopback.
