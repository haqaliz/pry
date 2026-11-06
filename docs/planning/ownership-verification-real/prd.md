# PRD — Ownership Verification, For Real (P1)

- **Status:** Merged to `master` (2026-11-07). The automated suite passes; the manual
  owner-domain check remains.
- **Owner:** aliz
- **Date:** 2026-11-06
- **Slug:** `ownership-verification-real`
- **Capability:** P1 (gates P2–P7)
- **Branch:** `feat/ownership-verification-real/aliz`

## Problem Statement

Pry's core promise is that nothing runs against a target the user has not proven they
control. The code does not enforce that promise.

| Claim | Reality |
|---|---|
| P1 verifies ownership | `src/pry/own/verification.py:43,60,78` return `(True, None)` for every method |
| `scan` requires a valid token | `src/pry/cli.py:114-120` accepts any non-empty string, then prints a simulated scan and exits 0 |
| Tests cover verification | `tests/own/test_ownership_verification.py:40` asserts `is_verified is True or error is not None`; it passes whether verification works or not |
| P1 is complete | `README.md:65`, `docs/planning/ownership-verification/IMPLEMENTATION_SUMMARY.md:3` |
| P3 is implemented | Commit `6dda41d` says so; no `src/pry/probes/` exists on `master` |

The gate is the product's trust boundary, not a feature. Today a user can point Pry at
any host, pass `--token x`, and the tool reports a successful scan. Every downstream
capability (P2–P6) would inherit that bypass. R1 is rated Critical in
`docs/ROADMAP.md:50`.

**If we do not build this:** P2 and P3 cannot be built honestly. The first probe added
would run behind a check that never checks.

**What we are choosing not to build:** P2 intake, P3 probes, live scanning, OAuth
account linking, token revocation, and a hosted key service.

**Six-month failure scenario:** the real checks exist but are so awkward (two-step
challenge, confusing errors) that users pass arbitrary tokens or patch the gate out, and
the tool ships a false sense of safety. Mitigation: one clear challenge flow, named
failure causes, and a test suite that asserts the negative cases.

## Goals & Success Metrics

1. **No proof, no token.** A target without the published challenge cannot obtain an
   ownership token, at any intensity level.
2. **No valid token, no scan.** A missing, empty, malformed, tampered, expired, or
   wrong-target token stops `scan` before any target request.
3. **Honest output.** With no probe suite, `scan` reports `UNVERIFIED` and never exits 0.
4. **Accurate docs.** No document claims P1 or P3 is complete when it is not.

Success metrics:

- Every acceptance test in §8 passes offline; every negative case fails closed.
- The suite makes zero real DNS or HTTP calls (enforced by injection and a network guard).
- A manual run against a domain the owner controls completes both the DNS and
  well-known flows. This is a release check, not an automated test.
- `README.md` and the implementation summary contain no unsupported completion claim.

## User Personas & Scenarios

**App owner (solo developer).** Owns `example.com`, wants to scan the app deployed
there. They add one TXT record (or one file), run the verification command, receive a
token, and pass that token to `scan`.

**Maintainer.** Building P2/P3 next. They need an API where a probe can only receive a
validated `OwnershipToken`, not a user-supplied string.

**Scenario walkthrough:**

```bash
# 1. Ask for a challenge. Pry prints the exact record and the re-run command.
pry verify-ownership https://example.com --method dns

# 2. Publish the record, then check it.
pry verify-ownership https://example.com --method dns --challenge <nonce>
# -> token, exit 0; or a named failure, exit 1

# 3. Scan. The gate runs before anything else.
pry scan https://example.com --token <token>
# -> UNVERIFIED: probe suite not implemented, exit 1 (never 0)
```

## Requirements

### Must-have

| ID | Requirement |
|---|---|
| M1 | **Target normalization.** Accept an absolute URL or a bare host. Bare host defaults to `https://`. Reject non-http(s) schemes, userinfo, and empty hosts. Lowercase, IDNA-encode, strip a trailing dot, drop default ports. Bind the token to the origin (`scheme://host[:port]`). |
| M2 | **DNS TXT check.** Query `_pry.<host>` and require a TXT value exactly equal to `pry-verify=<challenge>`. Reject IP-literal targets for this method. |
| M3 | **Well-known check.** Fetch `<origin>/.well-known/pry-ownership.txt` and require the body to equal `pry-verify=<challenge>` after stripping one trailing newline. Require HTTPS, except loopback (`localhost`, `127.0.0.1`, `::1`) for local fixtures. |
| M4 | **Fail closed with named causes.** Wrong or missing record/content, NXDOMAIN, timeout, non-200, TLS failure, cross-host redirect, and insecure transport all produce no token and a specific cause. Never a traceback. |
| M5 | **Signed token.** `pry1.<base64url(payload)>.<base64url(hmac)>`; HMAC-SHA256 with a local key; payload binds version, normalized origin, proof type, issued-at, and expiry (24h). Validation checks signature (constant time), version, target, and expiry. |
| M6 | **Key handling.** Default key `~/.pry/ownership.key`, 32 random bytes, directory `0700`, file `0600`, created with `O_CREAT|O_EXCL`. `PRY_KEY_FILE` overrides the path. A wrong-size or unreadable key is a named error, not a silent regeneration. |
| M7 | **Structural gate.** `scan` validates the token and passes a validated `OwnershipToken` object to the scan entry point. No probe may receive the raw token string. Invalid token → exit 2 before any target request. |
| M8 | **Honest scan behavior.** Only level 0 is accepted. Levels 1–2 exit 2 with `INTENSITY_INSUFFICIENT`. With a valid token and no probe suite, print `UNVERIFIED: PROBE_INCONCLUSIVE` and exit 1. Never exit 0. |
| M9 | **Remove account linking.** Delete the CLI flags and the `account_link` code path until a real OAuth flow exists. Do not leave a method that always succeeds. |
| M10 | **Working CLI and package.** One packaging source (`pyproject.toml`), package dir `src`, imports `pry.*` (not `src.pry.*`), synchronous `main()` entry point. `uv run pry --help` and `uv run pytest` both work from a clean checkout. |
| M11 | **Offline tests.** Replace the tautological tests with positive and negative assertions. Inject the DNS resolver and use a loopback HTTP fixture. A network guard fails the test if a real DNS/HTTP call escapes. |
| M12 | **Correct the record.** Update `README.md`, fix or replace `docs/planning/ownership-verification/IMPLEMENTATION_SUMMARY.md`, and remove the false "P3 implemented" implication where it is repeated in docs. |

### Should-have

| ID | Requirement |
|---|---|
| S1 | `scan --token-file PATH` so tokens do not land in shell history. `--token` stays for tests and scripting. |
| S2 | One documented test command; delete `run_tests.py`, which imports classes that do not exist and duplicates the suite. |
| S3 | `--json` output for `verify-ownership` so scripts do not parse prose. |

### Nice-to-have (not this change)

DNSSEC validation, token revocation, key rotation, real OAuth account linking,
per-target keys.

## Technical Considerations

**Pipeline position.** P1 is first. P2/P3 do not exist on `master`; the unmerged
`feat-target-intake-aliz` worktree is out of scope and must not be used as a dependency.

**Challenge flow.** The verification command has two modes:

- Without `--challenge`: generate a 32-byte URL-safe nonce, print the exact DNS record
  or file content and the re-run command, exit 1. This is an instruction step, not a
  verification.
- With `--challenge`: validate the nonce shape (32 bytes URL-safe), perform the lookup
  or fetch, and compare exactly.

The nonce is unguessable and prefixed with `pry-verify=`. This defeats the obvious
attack of passing a TXT value that already exists on the victim's domain: the existing
record would also have to start with that marker and contain a 32-byte random value.

**Token format.**

```json
{"v":1,"target":"https://example.com","proof":"dns_txt","iat":1762370000,"exp":1762456400}
```

Canonical JSON (`sort_keys`, no spaces), HMAC over the payload bytes, base64url without
padding. The key never leaves the machine. Verification is same-machine only; this is a
CLI, not a hosted service.

**HTTP policy.** Timeout 5s, response cap 4 KiB, no automatic cross-host redirects.
A redirect chain that ends on a different host is `WELL_KNOWN_REDIRECT`. TLS
verification uses the standard library defaults. `http://` is accepted only for
loopback so tests can run locally without certificates.

**DNS implementation.** `dnspython` (user decision), system resolver by default.
Inject a `resolve_txt(name) -> list[str]` callable so tests never touch the network.
The lookup name is derived from the normalized host, never from the path.

**Synchronous internals.** The current async CLI exists for no concurrency reason and
produces a broken console entry point (`main` returns a coroutine that is never
awaited). Make verification and the CLI synchronous; the entry point becomes
`pry = pry.cli:main`.

**Packaging.** `setup.py` and `setup.cfg` do not install `src/pry` (`find_packages()`
finds nothing because `src/pry/__init__.py` is missing). Replace them with a
`pyproject.toml` that sets `package-dir = {"" = "src"}`, declares `dnspython>=2.6`,
and configures pytest with `pythonpath = ["src"]`. Keep `pytest-asyncio` out unless a
test genuinely needs it.

**Data touched.** One DNS TXT query and one GET of a fixed path. No crawling, no
authentication, no cookies, no request body. This is read-only by construction.

**Error causes.** `DNS_RECORD_NOT_FOUND`, `DNS_MISMATCH`, `DNS_ERROR`,
`WELL_KNOWN_NOT_FOUND`, `WELL_KNOWN_MISMATCH`, `WELL_KNOWN_REDIRECT`,
`WELL_KNOWN_ERROR`, `INSECURE_TRANSPORT`, `UNSUPPORTED_TARGET`, `BAD_CHALLENGE`,
`NO_METHOD`, `UNSUPPORTED_METHOD`, `TOKEN_MALFORMED`, `TOKEN_BAD_SIGNATURE`,
`TOKEN_EXPIRED`, `TOKEN_TARGET_MISMATCH`, `KEY_INVALID`.

**Exit codes.** `verify-ownership`: 0 verified, 1 not verified or challenge issued,
2 usage error. `scan`: 0 only for a completed scan with no reproduced finding (not
reachable until P3), 1 for `UNVERIFIED`/`EXPOSED`, 2 for usage, invalid token, or
unsupported intensity.

## Risks & Open Questions

| Risk | Severity | Mitigation |
|---|---|---|
| **R1 residual:** DNS TXT is unauthenticated without DNSSEC; an on-path attacker could spoof a response | Med/High | Use the system resolver; document DNSSEC as a future hardening; well-known requires HTTPS |
| **Token theft:** the token is a bearer credential until expiry | Med/Med | 24h expiry, 0600 key, `--token-file` (S1), target binding, no token in logs |
| **Local key compromise:** anyone who can read the key can forge tokens | Low/High | 0600 file, 0700 directory, no key in the repo, named failure on invalid key |
| **Two-step UX** causes users to pass arbitrary challenges or abandon verification | Med/Med | Print the exact record and re-run command; one clear error per cause |
| **Packaging refactor** breaks imports or the console script | Med/Low | One source of truth, end-to-end CLI tests, `uv run pytest` from clean checkout |
| **A determined user patches the gate out** | Low/Med | Out of threat model: the gate exists so Pry itself never scans an unowned target, not as DRM. Document this. |

Open questions:

- Should the challenge itself be HMAC-signed and target-bound, removing the small
  residual "existing `pry-verify=` record" window? Deferred; the 32-byte random value
  makes it impractical.
- Should `scan` read the token from stdin as well as `--token-file`? Decide in tech plan.
- Should the token bind the path as well as the origin? No: origin-level ownership is
  the intended scope. Revisit if multi-tenant paths need isolation.

**The hard question before greenlighting:** if the gate is only as strong as the
verification methods, and DNS TXT without DNSSEC is spoofable, what does "proven
ownership" mean for a user on a hostile network? The answer for v1 is that the
well-known method over HTTPS is the stronger path and DNS is the convenient one; the
verdict space still never says "secure," and the proof bundle records which method was
used.

## Out of Scope

- P2 target intake, P3 floor probes, P4 intensity-gated probes, P5 proof capture,
  P6 corpus/report, P7 platform integration.
- Any live-target scanning or exploit attempt.
- Real OAuth account linking.
- Token revocation, key rotation, multi-user or hosted key management.
- DNSSEC validation.
- Changes to the unmerged P2/P3 worktree.

## Acceptance Tests

| ID | Test | Expected |
|---|---|---|
| AT1 | Normalize `example.com`, `https://EXAMPLE.com:443/`, `https://example.com./app` | All → `https://example.com` |
| AT2 | Reject `ftp://example.com`, `https://user:pass@example.com`, empty host | `UNSUPPORTED_TARGET`, exit 2 |
| AT3 | DNS: resolver returns `pry-verify=<nonce>` | Verified, token issued |
| AT4 | DNS: wrong value, empty answer, NXDOMAIN, timeout | Not verified; `DNS_MISMATCH` / `DNS_RECORD_NOT_FOUND` / `DNS_ERROR` |
| AT5 | Well-known: 200 with exact body | Verified, token issued |
| AT6 | Well-known: 404, wrong body, cross-host redirect, `http://` non-loopback | Not verified; matching cause |
| AT7 | Token round-trip | Validates for the same origin, rejects a different origin |
| AT8 | Tampered payload/signature, expired token, malformed token, wrong key | Each rejected with the matching cause |
| AT9 | `verify-ownership` without `--challenge` | Prints record/file instructions, exits 1, no token |
| AT10 | `verify-ownership` with correct / incorrect challenge | Exit 0 + token / exit 1 + cause |
| AT11 | `scan` with absent, empty, garbage, wrong-target, expired token | Exit 2; post-gate function never called; no network |
| AT12 | `scan` with valid token, level 0 | `UNVERIFIED: PROBE_INCONCLUSIVE`, exit 1 |
| AT13 | `scan --level 1` or `--level 2` | Exit 2, `INTENSITY_INSUFFICIENT` |
| AT14 | Full suite | Passes offline; network guard asserts zero real calls |
| AT15 | Docs | No "P1 complete" or "P3 implemented" claim remains |

## Self-Critique (before sharing)

- 🟡 **Real-domain confidence.** All automated tests are offline, so the real resolver
  and TLS path are only exercised by the manual release check. Acceptable for v1;
  the alternative is a flaky network-dependent suite.
- 🟡 **Token model is bearer.** A leaked token is usable until expiry. `--token-file`
  and a short expiry reduce exposure; revocation is future work.
- 🟡 **Packaging is bundled into a security fix.** It is required for the CLI to run,
  but it enlarges the diff. Keep it mechanical and covered by AT14/AT15.
- 🟢 **Problem and scope are explicit**, and every must-have has a testable criterion.

**Resolved before build:** local-key HMAC is the v1 ownership token. "Independently
verifiable" in the architecture text is read as same-machine verification for the CLI
slice; asymmetric signing is deferred to the P5 proof-bundle work.
