# Aspect Spec — Read-Only Floor Probes

- **Feature:** `floor-probes-real`
- **Aspect:** `read-only-probes`
- **PRD:** `../prd.md`
- **Status:** Approved on standing instruction (2026-11-07)

## Problem slice

Turn a P2 sandbox into a local scan: run three read-only probes inside the sandbox, capture
the request/response pair, and emit a verdict. No live URLs, no authenticated checks, no
write-based confirmation.

## In scope

- Per-run Docker `--internal` network; app alias `app`; Python probe sidecar; `docker exec`.
- Three probes: CORS with credentials, verbose error leakage, exposed secret files.
- `ProbeResult` / `ScanResult` model, redaction, `results.json`.
- `pry scan PATH` for local directories; URL path unchanged and still `UNVERIFIED`.
- Offline unit tests; opt-in Docker tests on vulnerable/safe fixtures.
- ETHICS.md approved before probe code; docs truth updated.

## Out of scope

- Missing auth, IDOR/access control, exposed database/open rules.
- Header-only findings, live URL probing, levels 1–2, writes.
- Signed proof bundles (P5), reports (P6).

## Acceptance criteria

PRD AT1–AT15. Every AT maps to a test in the plan.

## Dependencies and sequencing

- P1 and P2 are merged on `master` (`9c5a858`).
- ETHICS.md is in this branch and must remain; no probe code without it.
- Python 3.9; no new dependencies. Docker is external.
- P2's default `intake` stays `--network=none`; P3 adds an opt-in internal-network mode so
  P2 tests and behavior do not regress.

## Open questions

None blocking. CORS is reported as the reproduced header pair, not as data theft.
