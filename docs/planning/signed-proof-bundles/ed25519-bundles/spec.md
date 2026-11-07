# Aspect Spec — Ed25519 Proof Bundles

- **Feature:** `signed-proof-bundles`
- **Aspect:** `ed25519-bundles`
- **PRD:** `../prd.md`
- **Status:** Implemented and merged (2026-11-08)

## Problem slice

Sign every EXPOSED local finding with Ed25519 and add a verifier. The bundle is
self-contained: target snapshot, finding, public key, fingerprint, signature. Other verdicts
are not signed.

## In scope

- `cryptography` dependency; key at `~/.pry/proof.key` (0600).
- Canonical payload, bundle, signature, fingerprint.
- Scan writes bundles for EXPOSED; `proof` path in `results.json`.
- `pry verify-proof FILE [--fingerprint]`; VALID/INVALID; exit 0/1.
- Offline unit tests; Docker integration; docs.

## Out of scope

- P4/live URL/remaining P3; key distribution/revocation; hosted verification; live replay.
- Any "secure" claim.

## Acceptance criteria

PRD AT1–AT13. Every AT maps to a test in the plan.

## Dependencies and sequencing

- P1–P3 and ETHICS.md are merged.
- `cryptography` pinned `<47`; Python 3.9.6.
- Default suite offline; Docker tests opt-in.
