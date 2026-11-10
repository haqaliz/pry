# Pry: Architecture

Design intent, not built behavior. P1 is implemented; P2 local intake is implemented; P3
read-only probes are implemented; P5 read-only signed bundles are implemented for local and
live read-only findings; P6 local report/corpus are implemented; live read-only scans and
configured live IDOR and configured local IDOR are implemented; local Level 1 SSRF and a
bounded local rate-limit observation are implemented; live write-based checks, live SSRF, live
rate-limit, Level 2, general authenticated scanning, hosted reports, and the rest of P5 are
design intent.

## Pipeline

```
target (local repo | live URL)
        |
        v
  P1 ownership verification  (DNS TXT | well-known file; account-link deferred)
        |  (gates everything below, at every intensity, including level 0)
        v
  P2 intake  ---->  pinned snapshot (sandbox boot, or recorded live endpoint set)
        |
        v
  P3 floor probes (read-only, always on)
        |
        v
  P4 intensity-gated probes (level 1 read-only expanded, level 2 write-based, confirmed)
        |
        v
  P5 proof capture  ---->  EXPOSED | NOT_REPRODUCED | UNVERIFIED  (+ named cause)
        |
        +-->  P6 findings corpus / report
```

## Layout (planned)

```
src/pry/
  own/        P1: verification methods, proof tokens
  intake/     P2: local repo sandbox boot (live URL deferred)
  probe/      P3: read-only sidecar probes (CORS, errors, secrets, declared unauth endpoints) + live read-only + configured live/local IDOR; P4 Level 1 local SSRF (callback) + rate-limit observation
  proof/      P5: Ed25519 signed bundles for local findings (live replay deferred)
  report/     P6: local HTML report and JSONL corpus (hosted/public deferred)
  cli/        pry scan | verify-ownership | intake | verify-proof | report
tests/        offline; fixture apps under local sandbox control; no real third-party targets
```

## Key decisions

- **Ownership gate is structurally first.** Every code path that reaches a probe passes through
  P1's check; this is enforced in the type/call structure, not just documented.
- **Local intake is a copied tree in Docker.** Only a temporary copy is mounted; the run
  container has no egress, no host socket, a non-root user, and resource limits. The snapshot
  pins what ran.
- **Local probes run from a sidecar on an internal network.** The app and the sidecar share a
  per-run Docker `--internal` network; the host runs the probes through `docker exec`. Neither
  container has egress. Secrets are redacted inside the sidecar before the host sees them.
- **Live read-only scans run from the host after P1.** No sandbox; the token authorizes the
  origin. GET-only, no credentials, 4–6 requests. The same probe functions and proof/report
  path are used, so local and live cannot drift.
- **Configured live IDOR and local IDOR are credential-safe.** Two identities, two object
  paths, three GETs; the 0600 config is read once. Both controls must pass before the cross
  request can be EXPOSED. The local config is mounted read-only at `/pry-config/idor.json` in
  the sandbox and removed afterward. Stored auth/cookie headers are redacted; no config path or
  credentials are reported. No discovery or non-configured sweep.
- **Local SSRF Level 1 is callback-proven.** A callback sidecar on the internal network logs a
  per-run nonce; `EXPOSED` only on a hit. `--confirm` is required, the callback has no egress,
  and live SSRF is deferred. A hit proves an internal fetch, not external egress.
- **Rate-limit is an observation, not a verdict.** A bounded local sample reports
  `OBSERVED`/`THROTTLED`/`UNVERIFIED` in a separate, unsigned section. It never becomes
  `EXPOSED`; live rate-limit is deferred because of load/lockout risk.
- **The missing-auth probe only requests declared paths.** The owner supplies path-only
  declarations; absolute URLs and protocol-relative paths are rejected on the host and in the
  sidecar. The result quotes the declaration and the response, not a global auth conclusion.
- **Floor probes are read-only by construction.** Each floor check's implementation is reviewed
  for side effects (a GET that happens to trigger a webhook is not "read-only").
- **Confirmation is explicit and per-target.** Raising intensity requires a fresh confirmation for
  each target, not a global setting; a live target at level 2 requires an additional step beyond
  the standard warning.
- **Proof capture is minimal and redacted.** Only the bytes needed to demonstrate the finding are
  retained; anything beyond that is truncated or redacted before storage.
- **Findings are signed.** Every `EXPOSED` local or live read-only finding gets an Ed25519
  bundle over the target snapshot and the redacted pair. The embedded key is tamper-evidence;
  fingerprint pinning is the trust anchor. The signature is not a security verdict.
- **The report is a local view, not signed evidence.** It renders the run's snapshot/results,
  verifies each proof, and escapes every dynamic value. It works for local and live read-only
  runs. The signed bundles remain the evidence; no upload by default.
- **Determinism and replay.** Local findings get signed bundles; live replay and independent
  key distribution are future P5 work.
- **UNVERIFIED causes** (draft): `OWNERSHIP_UNVERIFIED`, `TARGET_UNREACHABLE`,
  `INTENSITY_INSUFFICIENT`, `SANDBOX_BOOT_FAILED`, `PROBE_INCONCLUSIVE`.

## CLI shape (target)

`pry verify-ownership <target>` — runs the proof flow, issues a signed ownership token.
`pry scan <target> --token TOKEN [--level 0|1|2] [--confirm] [--out DIR] [--json]`

Exit 0 on `NOT_REPRODUCED`/clean, 1 on any `EXPOSED`, 2 on usage or ownership failure. Never a
traceback.

## Open questions

- Sandbox boot strategy per target framework (Node/Next, Python, static) for local-repo intake.
- Whether a crypto-subscription hosted tier needs its own service component, or stays CLI-only
  with a license-key check — decide once Phase 3 is reached.
- PyPI distribution name: `pry` is taken; `pryhq` was free when checked.
