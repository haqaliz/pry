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
credentials. IDOR/access control, exposed database rules, live URL intake, and intensity
levels 1–2 are not started. A clean P3 result is `NOT_REPRODUCED`, never "secure."

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
token: the user already has the files. A URL still requires the P1 token and remains
`UNVERIFIED` because live probing is not implemented.

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

## Architecture

Pry's core architecture follows:

1. **OWN** (Ownership verification) — P1 capability
2. **INTAKE** (Target intake) — P2 local sandbox implemented; live URL deferred
3. **PROBE** (Security checks and exploitation) — P3 read-only first slice implemented
4. **PROVE** (Proof capture)
5. **REPORT** (Findings presentation)

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

# Scan a verified URL (live probes are not implemented yet)
pry scan https://example.com --token <token>
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
6. Live URL scans still lead to `UNVERIFIED`, never a success verdict.
7. Absence of a reproduced finding is never reported as "secure".

## Contributing

All capabilities implemented in Pry follow the test-first approach — failing tests are
written first and then implemented.

## License

Apache-2.0
