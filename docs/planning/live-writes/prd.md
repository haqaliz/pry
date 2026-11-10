# PRD — Live Level 2 Write Confirmation (P4 remainder)

- **Status:** Approved on standing instruction (2026-11-11)
- **Owner:** aliz
- **Slug:** `live-writes`
- **Capability:** P4 — live write confirmation with an extra explicit step

## Problem Statement

The live path can prove read exposures but rejects every write. A write check is the strongest
evidence of missing access control, but a live write can alter real data. Constraint 6 allows
it only when the owner explicitly raises the intensity with a full warning. The implemented
local slice already has the safe mechanics: a declared write, a unique marker, and a
verification read. The live slice adds the extra confirmation and runs the same mechanics
against a P1-verified origin.

## Goals & Success Metrics

1. `pry scan <url> --token <token> --level 2 --confirm --confirm-live-write --write-config FILE`
   runs one declared write and one verification read.
2. `EXPOSED` only when the write is 2xx and the verification read is 2xx and contains the
   generated marker; signed and reportable.
3. Missing either confirmation, the token, or a valid config exits 2 before any request.
4. No DELETE, uploads, auth, or multi-step workflows.
5. Docs state the staging preference, the lack of rollback, and the risk.

## Requirements

| ID | Requirement |
|---|---|
| M1 | Live `--level 2` requires `--confirm`, `--confirm-live-write`, `--write-config`, and a P1 token. |
| M2 | Reuse `WriteConfig`/`probe_write`; one declared POST/PUT/PATCH, marker substitution, one verification GET. |
| M3 | `EXPOSED` only for write 2xx + verify 2xx + marker; sign the proof; nest the verification pair. |
| M4 | 401/403/404 or absent marker → `NOT_REPRODUCED`; 5xx/transport → `UNVERIFIED`. |
| M5 | The write runs after the read-only probes; no sandbox; no rollback. |
| M6 | Missing confirmation/token/config, or SSRF flags → exit 2 before any request. |
| M7 | Tests: live scan, CLI gate, loopback integration; no third-party target. |
| M8 | Docs/ETHICS: extra flag, staging preference, no rollback, risk, no secure. |

## Technical Considerations

- `scan_live(..., write_config=None)`: validate the token first, then run `probe_write` in
  process after IDOR; append `ProbeResult(**result)`; finalize signs EXPOSED.
- CLI: add `--confirm-live-write`; URL level 2 requires it and `--write-config`; reject SSRF
  flags; allow live rate-limit if flags are present; level 0/1 with write config exits 2.
- The config is already in memory; do not write it to the run directory.
- No new dependencies; no Docker; the loopback test uses 127.0.0.1 only.

## Risks

| Risk | Severity | Mitigation |
|---|---|---|
| **Live write alters real data.** | High/Critical | Extra `--confirm-live-write`; P1 token; docs say staging/disposable; no rollback. |
| **False `EXPOSED` from a static marker.** | High/High | Unique per-run marker in the body and verification. |
| **A weak verification path.** | Med/High | Owner declares it; absence is `NOT_REPRODUCED`, not EXPOSED. |
| **The write succeeds but verification fails, leaving data.** | Med/High | Docs warn; the result says the write was accepted but not confirmed; manual cleanup. |
| **Config path/body secrets leak.** | Med/High | Config 0600; no path in outputs; use test data. |

**Hard question:** a live write is the most dangerous check Pry can run. The extra confirmation
and the staging preference are the line; if the owner points it at production, that is their
explicit choice.

## Out of Scope

- DELETE, uploads, auth, multi-step workflows, rollback.
- IDOR discovery, provider DB rules, live SSRF, hosted reports.
- Writing without a P1 token.

## Acceptance Tests

| ID | Test | Expected |
|---|---|---|
| AT1 | Live write + verify marker | EXPOSED, signed, report |
| AT2 | Write 401/403/404 | NOT_REPRODUCED |
| AT3 | Write 2xx, marker absent | NOT_REPRODUCED |
| AT4 | Write 5xx/transport | UNVERIFIED |
| AT5 | Missing extra confirmation | exit 2, no request |
| AT6 | Missing token/invalid config | exit 2, no request |
| AT7 | SSRF flags on URL | exit 2, no request |
| AT8 | Loopback integration | write + verify, signed |
| AT9 | Docs | extra flag, staging, no rollback, risk |

## Self-Critique

- 🟡 **This is the sharpest edge in the product.** The extra flag and docs must be unmissable.
- 🟡 **No rollback.** The owner must use staging or a disposable record.
- 🟢 **The marker verification prevents a 2xx-only false positive.**
