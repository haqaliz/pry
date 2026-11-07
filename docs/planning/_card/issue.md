# Signed Proof Bundles (P5 read-only slice)

- **Type:** feat
- **Slug:** `signed-proof-bundles`
- **Owner:** aliz
- **Source:** inline brief. No GitHub issue.
- **Capability:** P5 read-only slice (M1.2). Depends on P1–P3 and `ETHICS.md`.

## Brief

Every `EXPOSED` finding from a local scan must ship as a signed, tamper-evident bundle that
can be verified without the scanner. Today `results.json` holds a redacted request/response
pair but no signature, no bundle id, and no independent verification. That is the gap
between "we saved something" and "here is the proof."

Use Ed25519. The bundle contains the finding payload (target snapshot, probe, verdict,
evidence, request, response), the public key, its fingerprint, and the signature. A new
`pry verify-proof <file>` command verifies the signature and prints the fingerprint. The
signature proves integrity and key possession; it does not prove the app is secure.
`NOT_REPRODUCED` and `UNVERIFIED` results are not signed.

## Current state

- P1, P2, P3 first slice, and declared unauthenticated endpoints are merged.
- Local scans write `results.json` plus `snapshot.json`; no signed bundles.
- `cryptography` is not a dependency yet.
- `ETHICS.md` is approved.

## Scope

1. Add `cryptography` (Ed25519) to `pyproject.toml`; Python 3.9 compatible.
2. Proof key: `~/.pry/proof.key` (32-byte seed, 0600), `PRY_PROOF_KEY` override, generated
   on first use with `O_CREAT|O_EXCL`.
3. Bundle: `version`, `created_at`, `payload` (target + finding), `signature`
   (`alg`, `public_key`, `fingerprint`, `value`), `bundle_id` = sha256 of canonical payload.
   Canonical JSON, sorted keys; signature over the payload bytes.
4. `pry scan` writes `proofs/<bundle_id>.json` for each `EXPOSED` result (0600), adds the
   bundle path to the result, and leaves `NOT_REPRODUCED`/`UNVERIFIED` unsigned.
5. `pry verify-proof <file> [--fingerprint sha256:...]`: VALID/INVALID, exit 0/1; prints the
   fingerprint and finding summary. Optional fingerprint pinning is the trust anchor.
6. Tests: sign/verify, tamper payload/signature/key, wrong fingerprint, malformed bundle,
   key/bundle permissions, scan writes only EXPOSED bundles, CLI, Docker integration.
7. Docs: the bundle, the trust model, and what the signature does not assert.

## Out of scope

- P4, live URL, IDOR/DB rules, remaining P3 checks.
- Key distribution, revocation, multi-user trust stores, hosted verification.
- Signing a claim about the whole app; only the reproduced finding is signed.

## Acceptance criteria

- A vulnerable local scan writes one bundle per `EXPOSED`; each verifies.
- A safe scan writes no bundles.
- Tampering with the payload or signature → INVALID.
- A different public key → INVALID; a mismatched `--fingerprint` → INVALID.
- The private key never appears in the bundle; key 0600, bundle 0600.
- `pry verify-proof` works from a copied bundle without the run directory.
- Default suite offline; Docker tests opt-in.
- No "secure" claim anywhere.
