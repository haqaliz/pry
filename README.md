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
leakage, exposed secret files, served database files, and declared-protected endpoints that
return 200 JSON with no credentials. P5 read-only signed proof bundles implemented for local
and live read-only EXPOSED findings. P6 local findings report and corpus implemented. Live
read-only scans and configured live IDOR checks are implemented for URLs with a P1 token;
configured local IDOR runs in the sandbox. Local Level 1 SSRF and bounded local/live
rate-limit observations are implemented with `--confirm`. Local and live Level 2 write
confirmation is implemented (live needs an extra confirmation). Opt-in response header
observations are implemented for local and live scans. IDOR discovery, provider
database/open-rule checks, live SSRF, and hosted/public reports are not started. A clean P3
result is `NOT_REPRODUCED`, never "secure."

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

The first slice checks six classes:

1. **CORS with credentials** — the response reflects `https://pry.invalid` and sets
   `Access-Control-Allow-Credentials: true`. `*` plus credentials is not reported as EXPOSED.
2. **Verbose error leakage** — a safe missing-path request returns a stack trace, framework
   debug page, or SQL error.
3. **Exposed secret files** — a fixed sensitive path returns a file containing a secret.
   Values are redacted before they leave the sidecar.
4. **Exposed database files** — a fixed path returns a SQLite header or a SQL dump at the
   start of the body. The stored body is a signature excerpt only; rows are never kept.
5. **Unauthenticated endpoints** — declare protected paths with `--endpoint`; a 200 JSON
   response with no `Authorization` or `Cookie` header is EXPOSED. 401/403/404, a redirect, a
   2xx HTML login page, or an empty body is NOT_REPRODUCED.
6. **Configured IDOR** — with `--idor-config`, two identities and two object paths; A→B
   200 JSON while both controls succeed is EXPOSED. Live and local; the config is 0600 and
   credentials are redacted.

The endpoint list is your declaration: Pry does not discover routes or infer auth from code.
The result is "this declared-protected path returned data with no credentials," not "the app
has no authentication." Endpoint discovery, IDOR discovery, provider database/open-rule
checks (Firebase, Supabase), and header policy analysis are deferred. See
[`ETHICS.md`](ETHICS.md) for what an exposure does and does not assert.

```bash
pry scan ./my-app
pry scan ./my-app --endpoint /api/users --endpoint /api/admin
pry scan ./my-app --json
```

The app and the probe sidecar share a per-run Docker internal network with no egress. The
host runs probes through `docker exec` into the sidecar; no host port is published. Exit
codes: 0 for no EXPOSED, 1 for any EXPOSED, 2 for usage/sandbox errors.

## Exposed Database Files

Every level 0 scan GETs `/data.db`, `/app.db`, `/db.sqlite`, and `/dump.sql` with no
credentials and no redirects. A same-origin 2xx response whose body starts with the SQLite
header (`SQLite format 3`) or with SQL-dump statements (`CREATE TABLE`, `INSERT INTO`,
`PRAGMA`, `BEGIN TRANSACTION`, `DROP TABLE`) is `EXPOSED` and signed.

The stored response body is a short signature excerpt, not the dump: rows and binary content
are withheld. 401/403/404, an HTML fallback, or no signature is `NOT_REPRODUCED`; a transport
failure is `UNVERIFIED`.

These are four conventional paths, not a database sweep. Provider rule checks (Firebase,
Supabase) are deferred: Pry cannot prove ownership of a third-party database host with the
current P1 methods.

## Live Read-Only Scans

`pry scan https://example.com --token <token>` validates the P1 token for the target origin,
then runs the same read-only probes from the host. There is no Docker sandbox for a live
target; the token is the authorization.

- GET-only; no `Authorization`/`Cookie`; no writes; up to 12 requests, plus one for
  `--headers`, one per `--endpoint`, three for configured IDOR, and up to five for a
  live rate-limit observation.
- CORS, verbose errors, exposed secret files, served database files, and declared
  `--endpoint` paths; same verdict rules as a local scan.
- Results are signed and reportable with `--report`; `--headers` adds an unsigned observation.
- A missing, invalid, or wrong-target token exits 2 before any request.
- Live SSRF is not implemented. Live Level 2 writes require a P1 token plus `--confirm` and
  `--confirm-live-write`, can alter real data, and are not rolled back; prefer staging. Live
  rate-limit is a bounded observation at level 1 with `--confirm`.

Live GETs are not zero-risk: a GET can trigger a webhook or cache. The user owns the target,
and Pry keeps the request count minimal.

## Configured IDOR Checks (Live)

IDOR is the companion to missing auth: a user who can read object A must not be able to read
object B. The check is configured, live-only, and read-only:

```json
{
  "identity_a": {"headers": {"Cookie": "session=a"}},
  "identity_b": {"headers": {"Cookie": "session=b"}},
  "object_a": "/api/items/1",
  "object_b": "/api/items/2"
}
```

```bash
chmod 600 idor.json
pry scan https://example.com --token <token> --idor-config idor.json --report
```

The config must be 0600. Pry runs three GETs: A→A (control), B→B (control), then A→B. The
cross request is `EXPOSED` only if it returns a 2xx JSON/non-empty body and both controls
succeed; 401/403/404 is `NOT_REPRODUCED`; a failed control or 5xx is `UNVERIFIED`. Stored
request/response headers redact `Cookie`, `Authorization`, `Set-Cookie`, and API key values.
The config path and credentials never appear in results, proofs, reports, or errors.

No discovery in this slice; the config declares the object pair.

## Local IDOR

```bash
chmod 600 idor.json
pry scan ./my-app --idor-config idor.json
```

The same config shape as live IDOR, but the three GETs run inside the sandbox. Pry validates
the 0600 config, writes a 0600 temp copy, mounts it read-only at `/pry-config/idor.json` in the
probe sidecar, and removes it afterward. `EXPOSED` only when A→A and B→B controls succeed and
A→B returns 2xx JSON. Stored request/response headers redact `Cookie`, `Authorization`,
`Set-Cookie`, and API-key values; the config path, temp path, and credentials never appear in
results, proofs, reports, logs, or errors.

No discovery and no non-configured sweep. The result is about the declared object pair, not a
global IDOR conclusion.

## Level 2 Write Confirmation (local and live)

```bash
chmod 600 write.json
pry scan ./my-app --level 2 --confirm --write-config write.json
```

For a live target, the extra confirmation is required:

```bash
pry scan https://staging.example.com --token <token> --level 2 --confirm \
  --confirm-live-write --write-config write.json
```

The config declares one write that should require auth and one read that proves it landed:

```json
{
  "method": "POST",
  "endpoint": "/api/items",
  "body": "{\"name\": \"{{marker}}\"}",
  "verify_endpoint": "/api/items",
  "verify_contains": "{{marker}}"
}
```

Pry replaces `{{marker}}` with a fresh `pry-<hex>`, sends the write with no credentials in
the disposable sandbox, then GETs the verification path. `EXPOSED` only when the write is
2xx and the verification read is 2xx and contains the marker; the signed proof carries both
the write pair and the verification pair. A rejected write or an absent marker is
`NOT_REPRODUCED`; a write 5xx or transport failure is `UNVERIFIED`.

POST, PUT, and PATCH only; no DELETE, uploads, auth, or multi-step workflows. Local runs use
the disposable sandbox. A live write requires a P1 token plus both `--confirm` and
`--confirm-live-write`; it can alter real data, **there is no rollback**, and the live URL
with `--write-config` exits 2 before any request unless both flags are present. Prefer a
staging copy or a disposable test record. The config is 0600 and removed. Use test data, not
real secrets.

## Response Header Observations

```bash
pry scan ./my-app --headers
pry scan https://example.com --token <token> --headers
```

One GET to `/`; the response is checked for `Content-Security-Policy`,
`X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, `Permissions-Policy`,
`Cross-Origin-Opener-Policy`, and `Strict-Transport-Security` (HTTPS only). The result is an
unsigned `OBSERVED` hardening observation with `missing`/`present` lists, or `UNVERIFIED` on
transport failure.

This is **not a verdict**: it is not `EXPOSED`, is not signed, and does not change the exit
code. A present header is not proof of security, a missing one is not proof of exploitability,
and a CDN/proxy may be the one setting them. Local and live; no auth, no writes, no new
confirmation.

## Local SSRF (Level 1)

```bash
pry scan ./my-app --level 1 --confirm \
  --ssrf-endpoint /api/fetch --ssrf-parameter url
```

Level 1 is expanded read-only work and requires `--confirm` for each run. The app stays in
the local sandbox. A callback sidecar joins the sandbox internal network as `pry-callback`;
Pry sends the declared endpoint a callback URL with a per-run nonce, and the app fetches it.
`EXPOSED` only when the callback records the nonce. The app responding without a hit is
`NOT_REPRODUCED`; a transport or callback-control failure is `UNVERIFIED`.

- GET query parameter only; no POST/body/header injection.
- The callback hit proves the app fetched an internal callback URL. It does **not** prove
  arbitrary external egress.
- No live SSRF (needs a public callback); local Level 2 write confirmation is separate.
- Missing `--confirm`, SSRF flags at level 0, or a URL with SSRF flags → exit 2.
- The callback sidecar has no egress and no host port; it is removed with the sandbox.

## Rate-Limit Observation (Level 1, local and live)

```bash
pry scan ./my-app --level 1 --confirm \
  --rate-limit-endpoint /login --rate-limit-count 10
```

Local: 1–20 sequential GETs to a declared endpoint. Live: 1–5 GETs, 0.5s apart, with an
explicit `--confirm`; stop on the first 429/503/`Retry-After`. It records what happened:

- All 2xx → `OBSERVED`: no throttling seen in N requests.
- 429/503/`Retry-After` → `THROTTLED` at request K.
- Transport/control failure → `UNVERIFIED`.

```bash
pry scan https://example.com --token <token> --level 1 --confirm \
  --rate-limit-endpoint /login --rate-limit-count 3
```

This is a **hardening observation, not a verdict**. It is not `EXPOSED`, is not signed, and
does not change the scan exit code. It appears in a separate Observations section of the
report and in `--json`. Live sampling can still cause load or a lockout on an auth endpoint:
the cap, spacing, stop-on-throttle, and explicit confirmation are the guardrails. Do not
point it at login or account-recovery paths on a shared target.

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
VALID/INVALID status. Hardening observations (such as a bounded rate-limit sample) appear in a
separate unsigned section. The report is a local view; the signed bundles are the evidence,
and the HTML itself is not signed.

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
3. **PROBE** (Security checks and exploitation) — P3 read-only + live read-only + live/local IDOR + database files + header observations; P4 Level 1 local SSRF + rate-limit observation + local/live Level 2 write confirmation
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

# Configured live or local IDOR (config must be 0600)
pry scan https://example.com --token <token> --idor-config idor.json
pry scan ./my-app --idor-config idor.json

# Local Level 1 SSRF (requires explicit confirmation)
pry scan ./my-app --level 1 --confirm \
  --ssrf-endpoint /api/fetch --ssrf-parameter url

# Local rate-limit observation (hardening, not a verdict)
pry scan ./my-app --level 1 --confirm \
  --rate-limit-endpoint /login --rate-limit-count 10

# Live rate-limit observation (hardening, max 5 GETs)
pry scan https://example.com --token <token> --level 1 --confirm \
  --rate-limit-endpoint /login --rate-limit-count 3

# Level 2 write confirmation (local sandbox; config must be 0600)
pry scan ./my-app --level 2 --confirm --write-config write.json

# Live Level 2 write (extra confirmation; can alter real data, no rollback)
pry scan https://staging.example.com --token <token> --level 2 --confirm \
  --confirm-live-write --write-config write.json

# Response header observation (hardening, not a verdict)
pry scan ./my-app --headers

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
   redacts secret values and database rows before the host sees them.
6. Every local or live `EXPOSED` result is an Ed25519-signed bundle; `verify-proof` checks
   the signature and fingerprint.
7. Live scans require a P1 token, are GET-only, send no credentials, and make up to 12
   requests; a live rate-limit observation adds up to five; configured live/local IDOR adds
   the credentials from a 0600 file to its three requests only.
   The local config is mounted read-only into the sandbox and removed afterward. Stored headers
   redact auth/cookie/API-key values.
8. Local Level 1 SSRF requires `--confirm`; the callback sidecar has no egress and a hit is
   the only EXPOSED condition. The rate-limit probe and header check are hardening
   observations, not verdicts. Live rate-limit is capped at five GETs, spaced 0.5s, and
   stops on the first throttle. Level 2 writes need a verification marker; local runs use the
   disposable sandbox, live runs require both confirmations, can alter real data, and are not
   rolled back. Live SSRF is not implemented.
9. The P6 report/corpus are local-only; no upload, and the HTML is not signed evidence. The
   report shows hardening observations separately from verdicts.
10. Absence of a reproduced finding is never reported as "secure".

## Contributing

All capabilities implemented in Pry follow the test-first approach — failing tests are
written first and then implemented.

## License

Apache-2.0
