# Pry - Security Exposure Scanner

**Pry proves that an app you own is exposed, by actually trying the exploit against it.**

## What This Is

Pry verifies security exposures in web applications by actually attempting exploits, never
by pattern-matching for "looks risky". Point Pry at a target you've proven you own — a live
URL or a local repo booted in a sandbox — and it runs a graduated set of checks, read-only
by default, and reports only what it could reproduce: the exact request, the exact response,
the data it should not have returned.

## Status

P1 ownership gate implemented. P2 local intake implemented. P3 read-only floor probes
implemented (first slice + missing-auth declarations): CORS with credentials, verbose error
leakage, exposed secret files, and declared-protected endpoints that return 200 JSON with no
credentials. P5 read-only signed proof bundles implemented for local and live read-only
EXPOSED findings. P6 local findings report and corpus implemented. Live read-only scans are
implemented for URLs with a P1 token. IDOR/access control, exposed database rules, live
write-based checks, hosted/public reports, and intensity levels 1–2 are not started. A clean
P3 result is `NOT_REPRODUCED`, never "secure."

## Ownership Verification (P1)

Every target must prove control before Pry will scan it, at every intensity level,
including the lowest.

### Methods Supported

1. **DNS TXT record** — publish `pry-verify=<challenge>` at `_pry.<host>`.
2. **Well-known file** — publish `pry-verify=<challenge>` at
   `https://<host>/.well-known/pry-ownership.txt`.

Account linking is not implemented, and the CLI does not accept it.

### How It Works

The first command issues a random challenge and prints exactly what to publish. The second
command checks it and issues an HMAC-signed token bound to the target's origin and valid for
24 hours.

```bash
# 1. Ask for a challenge; nothing is verified yet.
pry verify-ownership https://example.com --method dns

# 2. Publish the printed TXT record, then check it.
pry verify-ownership https://example.com --method dns --challenge <challenge>

# 3. Scan with the issued token.
pry scan https://example.com --token <token>
```

For the file method, use `--method well-known`. Well-known verification requires HTTPS,
except for loopback test targets.

## Local Sandbox Intake (P2)

`pry intake` copies a local repository into a Docker sandbox, installs and builds it with
network access, then runs it with no outbound network. Readiness is checked inside the
container; no host port is published. The original repository is never mounted or modified.

Supported in this slice: static sites (`index.html`) and npm-based Node/Next projects with
a `start` or `dev` script. Python, yarn/pnpm, and live URL intake are deferred.

```bash
# Boot a local repo and write a pinned snapshot.
pry intake ./my-app

# Keep the container and workspace for debugging.
pry intake ./my-app --keep

# Machine-readable result.
pry intake ./my-app --json
```

The snapshot is written to `~/.pry/runs/<id>/snapshot.json` (or `--out DIR`) beside capped
`build.log` and `run.log` files. It records the git commit, dirty state, tree hash, lockfile
hash, image digest, build/start commands, port, container id, and sandbox network mode.

**Docker is required.** The sandbox is not a kernel-level security boundary: it contains
accidents and ordinary build scripts, not a determined kernel attacker. Build scripts run
third-party dependency code with network access; the run phase has no egress. There is no
Docker socket and no host filesystem mount beyond the temporary copy.

## Read-Only Floor Probes (P3)

`pry scan ./my-app` boots the local repo in the sandbox, runs the read-only floor probes,
writes `results.json` beside the snapshot, and cleans up. A local path needs no ownership
token: the user already has the files. A URL requires the P1 token and runs the same read-only
probes against the live origin.

The first slice checks four classes:

1. **CORS with credentials** — the response reflects `https://pry.invalid` and sets
   `Access-Control-Allow-Credentials: true`. `*` plus credentials is not reported as EXPOSED.
2. **Verbose error leakage** — a safe missing-path request returns a stack trace, framework
   debug page, or SQL error.
3. **Exposed secret files** — a fixed sensitive path returns a file containing a secret.
   Values are redacted before they leave the sidecar.
4. **Unauthenticated endpoints** — declare protected paths with `--endpoint`; a 200 JSON
   response with no `Authorization` or `Cookie` header is EXPOSED. 401/403/404, a redirect, a
   2xx HTML login page, or an empty body is NOT_REPRODUCED.

The endpoint list is your declaration: Pry does not discover routes or infer auth from code.
The result is "this declared-protected path returned data with no credentials," not "the app
has no authentication." Endpoint discovery, IDOR/broken access control, exposed database
rules, and header-only findings are deferred. See [`ETHICS.md`](ETHICS.md) for what an
exposure does and does not assert.

```bash
pry scan ./my-app
pry scan ./my-app --endpoint /api/users --endpoint /api/admin
pry scan ./my-app --json
```

The app and the probe sidecar share a per-run Docker internal network with no egress. The
host runs probes through `docker exec` into the sidecar; no host port is published. Exit
codes: 0 for no EXPOSED, 1 for any EXPOSED, 2 for usage/sandbox errors.

## Live Read-Only Scans

`pry scan https://example.com --token <token>` validates the P1 token for the target origin,
then runs the same four read-only probes from the host. There is no Docker sandbox for a live
target; the token is the authorization.

- GET-only; no `Authorization`/`Cookie`; no writes; 4–6 requests.
- CORS, verbose errors, exposed secret files, and declared `--endpoint` paths; same verdict
  rules as a local scan.
- Results are signed and reportable with `--report`.
- A missing, invalid, or wrong-target token exits 2 before any request.
- Rate-limit probing, SSRF, write-based checks, and levels 1–2 are not implemented.

Live GETs are not zero-risk: a GET can trigger a webhook or cache. The user owns the target,
and Pry keeps the request count minimal.

## Signed Proof Bundles (P5 read-only slice)

Every `EXPOSED` local or live read-only finding writes an Ed25519-signed bundle at
`~/.pry/runs/<id>/proofs/<bundle_id>.json`. The bundle contains the target snapshot (local
commit/tree/image or live URL/ownership proof) and the redacted request/response pair. The
signature covers that payload; the bundle carries the public key and its fingerprint.

```bash
pry verify-proof ~/.pry/runs/<id>/proofs/<bundle_id>.json
pry verify-proof <bundle> --fingerprint sha256:<your-key-fingerprint>
```

`verify-proof` prints `VALID`/`INVALID`, the fingerprint, and the finding. The proof key is
`~/.pry/proof.key` (0600, `PRY_PROOF_KEY` override). `NOT_REPRODUCED` and `UNVERIFIED` are not
signed.

The signature proves the captured pair was not altered after signing, and that the signer
held the private key. It does **not** prove the app is secure, and a bundle with an embedded
key is not provenance on its own: pin the fingerprint out-of-band to trust a specific signer.
Live replay and key distribution are future work.

## Findings Report and Corpus (P6 read-only slice)

`pry report RUN_DIR` or `pry scan ./app --report` writes a self-contained HTML report at
`RUN_DIR/report.html` (0600) from a local or live read-only run. It shows the target, verdict
counts, each finding's evidence and request/response, and each proof's fingerprint and
VALID/INVALID status. The report is a local view; the signed bundles are the evidence, and the
HTML itself is not signed.

The corpus appends one JSONL line per result to `~/.pry/corpus.jsonl` (`PRY_CORPUS` override),
0600. A corpus write failure is a warning, not a scan failure.

Local only: no upload, no hosted link, no PDF/email. Every dynamic value is HTML-escaped, and
there is no JavaScript or external asset. A safe report says `NOT_REPRODUCED`, never "secure."

```bash
pry scan ./my-app --report
pry report ~/.pry/runs/<id>
```

## Architecture

Pry's core architecture follows:

1. **OWN** (Ownership verification) — P1 capability
2. **INTAKE** (Target intake) — P2 local sandbox implemented; live read-only scans bypass it
3. **PROBE** (Security checks and exploitation) — P3 read-only first slice + live read-only
4. **PROVE** (Proof capture) — P5 read-only signed bundles for local and live findings
5. **REPORT** (Findings presentation) — P6 local report/corpus; hosted/public deferred

## Key Constraints

- No scan without owner verification
- Read-only by default, higher intensity requires confirmation
- Never claim "secure" — only "exposed" or "not reproduced"
- Execution decides, never a guess
- Minimize data touched with proof capture only
- No destructive actions without an explicit sandboxed target

## Installation & Usage

Requires Python 3.9+, `uv`, and Docker for local intake.

```bash
uv sync
uv run pytest
uv run pry --help
```

Or install the package with `pip install -e .`.

```bash
# Prove ownership using the DNS TXT method
pry verify-ownership https://example.com --method dns

# After publishing the challenge, check it and print a token
pry verify-ownership https://example.com --method dns --challenge <challenge>

# Boot a local repo in the sandbox and write a snapshot
pry intake ./my-app

# Scan a local repo with the read-only floor probes
pry scan ./my-app

# Declare protected paths for the missing-auth check
pry scan ./my-app --endpoint /api/users --endpoint /api/admin

# Scan a verified URL with the read-only probes
pry scan https://example.com --token <token> --report

# Verify a signed proof bundle
pry verify-proof ~/.pry/runs/<id>/proofs/<bundle_id>.json

# Generate a local HTML report
pry scan ./my-app --report
pry report ~/.pry/runs/<id>
```

Docker integration tests are opt-in:

```bash
PRY_DOCKER_TESTS=1 uv run pytest -q -m docker
```

## Security Model

Pry implements a strict ownership gate with:

1. P1 ownership gate implemented and covered by offline tests.
2. HMAC-signed tokens bound to the normalized target origin, expiring after 24 hours.
3. `scan` refusing an absent, malformed, tampered, expired, or wrong-target token before
   any target request.
4. P2 local intake runs a temporary copy in Docker with no host socket, no host network
   during the run phase, a non-root user, a read-only root, dropped capabilities, resource
   limits, and guaranteed cleanup.
5. P3 local scans run read-only probes in an internal network with no egress; the sidecar
   redacts secret values before the host sees them.
6. Every local or live read-only `EXPOSED` result is an Ed25519-signed bundle; `verify-proof`
   checks the signature and fingerprint.
7. Live scans require a P1 token, are GET-only, send no credentials, and make 4–6 requests;
   write-based checks and levels 1–2 are not implemented.
8. The P6 report/corpus are local-only; no upload, and the HTML is not signed evidence.
9. Absence of a reproduced finding is never reported as "secure".

## Contributing

All capabilities implemented in Pry follow the test-first approach — failing tests are
written first and then implemented.

## License

Apache-2.0
