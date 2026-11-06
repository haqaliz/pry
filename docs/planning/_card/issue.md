# Ownership Verification, For Real (P1)

- **Type:** feat
- **Slug:** `ownership-verification-real`
- **Owner:** aliz
- **Source:** inline brief. `gh issue view ownership-verification-real` does not resolve
  (slug, not an issue number), so this file is the brief per the fallback path.
- **Capability:** P1 — ownership verification. Gates every other capability (P2–P7).

## Brief

Replace the mock P1 gate with a real, fail-closed ownership check. A target must prove
control through a real DNS TXT lookup or a real `.well-known` file fetch before
`pry scan` will run. Successful verification issues a signed token bound to the
normalized target with an expiry; `pry scan` validates signature, target, and expiry
before doing anything else. Account-linking is removed from the CLI until it is real.
The false "complete" and "P3 implemented" claims in the docs are corrected in the same
change.

## Current state (evidence)

| Claim | Reality |
|---|---|
| P1 verifies ownership | `src/pry/own/verification.py:43,60,78` return `(True, None)` unconditionally |
| Scan requires a valid token | `src/pry/cli.py:114-120` accepts any non-empty string, then prints a simulation |
| Tests cover verification | `tests/own/test_ownership_verification.py:40` asserts `is_verified is True or error is not None` — passes either way |
| P1 complete | `README.md:65`, `docs/planning/ownership-verification/IMPLEMENTATION_SUMMARY.md:3` |
| P3 implemented | Commit `6dda41d` says so; no `src/pry/probes/` exists on `master` |

## Scope (must-have)

1. Real DNS TXT lookup against a resolver; exact record match.
2. Real HTTPS fetch of the well-known file; exact content match.
3. Fail closed: wrong/missing content, NXDOMAIN, timeout, non-200, cross-host redirect → no token.
4. HMAC-signed token bound to the normalized target, with expiry and proof type.
5. `pry scan` validates the token; no/empty/garbage/wrong-target/expired token → exit 2
   before any target network call.
6. Account-linking removed from the CLI and README until implemented for real.
7. Offline tests: injected DNS resolver and a local HTTP fixture, no third-party targets.
8. Correct the false completion claims in `README.md` and the implementation summary.

## Out of scope

- P2 intake / sandbox boot.
- P3 floor probes (despite the commit message, none exist on `master`).
- Any live-target scanning.
- Real OAuth account linking.
- Token revocation, key rotation, multi-user/hosted concerns.

## Acceptance criteria

- Correct TXT record → verified; wrong or missing record → not verified.
- Correct well-known body at the fixed path → verified; 404, wrong body, or a redirect
  whose final host differs → not verified.
- DNS/HTTP errors (NXDOMAIN, timeout, connection failure) → not verified, with a named
  cause; never a traceback.
- Token is signed, target-bound, and expires; tampered, expired, and wrong-target tokens
  are rejected.
- `pry scan` exits 2 and makes no target request with an absent, empty, garbage,
  wrong-target, or expired token.
- A verification call with no method selected fails closed.
- The full suite runs offline and the previously tautological tests are replaced by
  positive and negative assertions.

## Notes

- Base branch `master`; branch `feat/ownership-verification-real/aliz`.
- Unmerged P2/P3 work exists in a separate worktree (`feat-target-intake-aliz`); it is
  not on `master` and is out of scope here.
- Open decisions for the interview: DNS resolver dependency, token key storage.
