# PRD — Signed Proof Bundles (P5 read-only slice)

- **Status:** Merged to `master` (2026-11-08). Read-only signed bundles implemented for
  local EXPOSED findings; live replay, key distribution, and the rest of P5 are deferred.
- **Owner:** aliz
- **Slug:** `signed-proof-bundles`
- **Capability:** P5 read-only slice (M1.2)

## Problem Statement

The product promise is "a reproduced exploit, with proof." Today `results.json` contains a
redacted request/response pair, but nothing binds it to the target snapshot, nothing detects
tampering, and a third party cannot verify it. That is a saved result, not a proof bundle.

This slice signs every `EXPOSED` local finding with Ed25519 and adds a `pry verify-proof`
command. The signature covers the target snapshot, probe, verdict, evidence, and the
request/response. It proves integrity and key possession. It does not prove the app is
secure, and it does not replace a live replay.

**If we do not build this:** the moat is a JSON file anyone can edit, and the "signed proof"
claim in `CLAUDE.md` is not true.

**What we are choosing not to build:** P4, live URL, remaining P3 checks, key distribution,
revocation, hosted verification.

## Goals & Success Metrics

1. Every `EXPOSED` local finding writes one signed bundle; `NOT_REPRODUCED` and `UNVERIFIED`
   are not signed.
2. `pry verify-proof <file>` verifies the signature and prints the fingerprint; tampering
   yields INVALID.
3. The private key never appears in the bundle; key is 0600, bundle is 0600.
4. A copied bundle verifies without the original run directory.
5. The trust model is explicit: the embedded public key proves integrity; pinning the
   fingerprint is the trust anchor.

Success metrics:

- Vulnerable fixture with three EXPOSED findings → three bundles, all VALID.
- Safe fixture → zero bundles.
- Tampered payload/signature/public key → INVALID.
- Wrong `--fingerprint` → INVALID.
- Default suite offline; Docker test opt-in.

## Requirements

### Must-have

| ID | Requirement |
|---|---|
| M1 | Add `cryptography` (Ed25519), Python 3.9 compatible. |
| M2 | Proof key `~/.pry/proof.key` (32-byte seed, 0600), `PRY_PROOF_KEY` override, create with `O_CREAT|O_EXCL`, wrong size → `PROOF_KEY_INVALID` (never silently regenerate). |
| M3 | Canonical payload: target snapshot (sandbox id, path, kind, git commit/dirty, tree hash, image/digest, port) + finding (probe, verdict, cause, evidence, request, response). Sorted JSON, no whitespace. |
| M4 | Bundle: `version`, `created_at`, `bundle_id` (sha256 of canonical payload), `payload`, `signature` (`alg: Ed25519`, `public_key`, `fingerprint`, `value`). No private key. |
| M5 | `pry scan` writes `proofs/<bundle_id>.json` for each EXPOSED result, 0600, atomic; adds `proof` to the result; leaves other verdicts unsigned. |
| M6 | `pry verify-proof FILE [--fingerprint sha256:...]`: validates shape, fingerprint match, and signature; prints `VALID`/`INVALID`, the fingerprint, and the finding summary; exit 0/1. |
| M7 | Signature failure must not fabricate a proof: signing errors → `PROOF_FAILED`, exit 2; the scan does not claim a signed result. |
| M8 | Tests: sign/verify round trip, tamper payload/signature/key, wrong fingerprint, malformed bundle, key/bundle perms, only EXPOSED signed, CLI, copied bundle, Docker integration. |
| M9 | Docs: what the signature asserts, what it does not, key path, fingerprint pinning, and that it is not a "secure" verdict. |
| M10 | No new egress; bundle is local; it contains the already-redacted result. |

### Should-have

- `pry verify-proof --json`.
- `pry proof-fingerprint` helper.
- A `proofs` index in `results.json`.

## Technical Considerations

**Crypto.** Ed25519 via `cryptography`. Private seed 32 bytes; public key raw 32 bytes;
signature 64 bytes. Fingerprint = `sha256:` + sha256(raw public key). Sign the canonical
payload bytes. Verify with `Ed25519PublicKey.from_public_bytes` and `public_key.verify`.

**Bundle shape.**

```json
{
  "version": 1,
  "created_at": "2026-11-08T...Z",
  "bundle_id": "<sha256 hex>",
  "payload": {
    "target": {"sandbox_id": "...", "path": "...", "kind": "node", "git_commit": "...",
               "git_dirty": false, "tree_sha256": "...", "image": "...",
               "image_digest": "...", "port": 3000},
    "finding": {"probe": "cors", "verdict": "EXPOSED", "cause": null,
                "evidence": "...", "request": {...}, "response": {...}}
  },
  "signature": {"alg": "Ed25519", "public_key": "base64", "fingerprint": "sha256:...",
                "value": "base64"}
}
```

`bundle_id` is the sha256 of the canonical payload. The signature covers the payload only;
the signature block and `created_at` are metadata. The verifier recomputes the canonical
payload, checks the fingerprint, and verifies.

**Trust model.** The bundle carries its public key. Anyone can generate a key and sign a
tampered bundle, so `verify-proof` alone proves integrity, not provenance. `--fingerprint`
pins the owner's key; the fingerprint can be shared out-of-band. This is documented; full
key distribution/revocation is out of scope.

**Key handling.** Default `~/.pry/proof.key`, env `PRY_PROOF_KEY`; 0600, directory 0700.
The private seed is never in the bundle or logs. If the key is lost, old bundles remain
verifiable but new ones use a new fingerprint; the user must re-pin.

**Scan integration.** `scan_local` has the full snapshot and results. After the sandbox is
cleaned, for each EXPOSED result it builds the target+finding payload, signs, writes the
bundle, and replaces the result with `proof=<path>`. Then it writes `results.json`. If
signing fails, the scan raises `PROOF_FAILED` and does not write `results.json`; the
finding remains in memory only, which is better than an unsigned claim.

**Redaction.** The sidecar already redacts secrets before the host sees the result; the
bundle contains that redacted pair. No raw secrets. P5 full may add richer redaction.

## Risks & Open Questions

| Risk | Severity | Mitigation |
|---|---|---|
| **Embedded key swapped** with an attacker key and re-signed. | Med/High | `--fingerprint` pinning; docs say verification alone is integrity, not provenance. |
| **Key loss** invalidates the ability to produce new bundles with the same fingerprint. | Med/Med | Document; old bundles remain valid; re-pin after rotation. |
| **`cryptography` dependency** on Python 3.9/macOS. | Low/Med | Pin `<47`, test on 3.9.6; wheels available. |
| **Signing failure after a successful scan** loses `results.json`. | Med/Med | Exit 2 with `PROOF_FAILED`; cleanup already done; the user fixes the key and reruns. |
| **Overclaiming**: "signed" read as "true" or "secure". | High/High | Docs and CLI say the signature proves integrity of the captured pair, not the app's security. |
| **Bundle contains sensitive response data.** | Med/High | Already redacted; local 0600; no upload. |

**Hard question:** if the verifier must trust an embedded key, is this "independently
verifiable" or just tamper-evident? This slice is tamper-evident plus pinning; independent
provenance needs a published key or a transparency log, which is future work.

## Out of Scope

- P4, live URL, IDOR/DB rules, remaining P3 checks.
- Key distribution, revocation, transparency logs, hosted verification, multi-user trust.
- Replaying a live request; the bundle is the recorded pair, not a live exploit.
- Claiming the app is secure.

## Acceptance Tests

| ID | Test | Expected |
|---|---|---|
| AT1 | Sign/verify a finding | VALID, same fingerprint |
| AT2 | Tamper payload | INVALID |
| AT3 | Tamper signature | INVALID |
| AT4 | Swap public key | INVALID |
| AT5 | Wrong `--fingerprint` | INVALID |
| AT6 | Malformed/missing fields | INVALID |
| AT7 | Key/bundle permissions | 0600; no private key in bundle |
| AT8 | Scan with EXPOSED + NOT_REPRODUCED | one bundle for EXPOSED only |
| AT9 | Safe scan | zero bundles |
| AT10 | Copied bundle without run dir | VALID |
| AT11 | CLI exit codes/JSON | 0 valid, 1 invalid |
| AT12 | Docker vulnerable/safe scan | bundles match EXPOSED; verify passes |
| AT13 | Docs truth | no "secure"; P5 read-only slice stated |

## Self-Critique

- 🟡 **Provenance is only as good as fingerprint pinning.** Say it plainly.
- 🟡 **Signing after cleanup** means a signing failure loses the result file. Exit 2 is honest,
  but the UX could be better; a future `--no-sign` is not offered because every EXPOSED
  must ship signed.
- 🟢 **The payload includes the target snapshot and the redacted pair**, so the bundle is
  self-contained and verifiable after the sandbox is gone.
