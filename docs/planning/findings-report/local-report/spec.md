# Aspect Spec — Local Report and Corpus

- **Feature:** `findings-report`
- **Aspect:** `local-report`
- **PRD:** `../prd.md`
- **Status:** Approved on standing instruction (2026-11-08)

## Problem slice

Turn a run directory (`snapshot.json`, `results.json`, `proofs/`) into a self-contained HTML
report, and bank each finding in a local JSONL corpus. Local-only; no upload.

## In scope

- Corpus append at 0600; failure is a warning.
- Report load/render/write; proof verification per finding; HTML escaping.
- `pry report` and `pry scan --report`.
- Offline tests; Docker integration; docs.

## Out of scope

- Hosted/public reports, PDF/email, P4/live URL/remaining P3, report signing.

## Acceptance criteria

PRD AT1–AT10. Every AT maps to a test in the plan.

## Dependencies and sequencing

- P1–P3, P5 signed bundles, ETHICS.md are merged.
- No new dependencies; Python 3.9; default suite offline.
