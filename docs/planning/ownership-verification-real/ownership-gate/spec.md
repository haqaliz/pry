# Aspect Spec — Ownership Gate

- **Feature:** `ownership-verification-real`
- **Aspect:** `ownership-gate`
- **PRD:** `../prd.md`
- **Status:** Approved (2026-11-07)

## Problem slice

Pry has no working ownership gate. This aspect replaces the mock verification with a
real DNS TXT / well-known check, issues a signed target-bound token, and makes `scan`
refuse to proceed without a valid one. It also makes the CLI installable and honest
about the absent probe suite.

## In scope

- Target normalization and rejection of unsupported targets.
- Real DNS TXT lookup via `dnspython`, with an injectable resolver for tests.
- Real `.well-known/pry-ownership.txt` fetch over HTTPS, with a loopback exception.
- Fail-closed causes for every negative path.
- HMAC-SHA256 token bound to the normalized origin, 24h expiry, local key file.
- A single gate function used by `scan`; probes receive a validated token object.
- Synchronous CLI and a working `pyproject.toml` entry point.
- Offline tests, including a network guard.
- Corrections to every doc that claims P1 or P3 is complete.

## Out of scope

- P2 intake, P3 probes, P4 intensity-gated probes, P5 proof bundles, P6/P7.
- Any live-target scanning.
- OAuth account linking.
- Token revocation, key rotation, hosted keys, DNSSEC.
- The unmerged P2/P3 worktree.

## Acceptance criteria

The PRD's AT1–AT15 are the acceptance criteria. The plan maps every AT to a test file
and a phase.

## Dependencies and sequencing

- Blocks P2 and P3. Nothing downstream starts first.
- No dependency on the unmerged `feat-target-intake-aliz` branch.
- Runtime dependency: `dnspython>=2.6,<3`. Dev dependency: `pytest>=7,<9`.
- Python `>=3.9` (the current machine is 3.9.6; avoid 3.10-only syntax).

## Open questions

None blocking. The PRD's HMAC-vs-asymmetric question is resolved as: HMAC for the
ownership token, asymmetric signing deferred to the P5 proof bundle.
