# PRD — Floor Probes, For Real (P3)

- **Status:** Draft, awaiting review gate (includes `ETHICS.md`)
- **Owner:** aliz
- **Date:** 2026-11-07
- **Slug:** `floor-probes-real`
- **Capability:** P3 (depends on P1, P2, and the ethics gate)
- **Branch:** `feat/floor-probes-real/aliz`

## Problem Statement

P1 proves ownership and P2 boots a local repo in a sandbox, but Pry still produces no
security result. `pry scan` always reports `UNVERIFIED` because there are no probes. P3 is
the first capability that actually sends a request that should have been blocked, captures
what came back, and decides `EXPOSED` only from that pair.

The first slice deliberately avoids checks that need an endpoint inventory or two identities.
It covers three mechanical, read-only classes that can be reproduced against a running app:

1. **CORS with credentials** — an attacker origin is reflected and credentials are allowed.
2. **Verbose error leakage** — a safe malformed request returns a stack trace, framework
   debug page, or SQL error.
3. **Exposed secret files** — a fixed sensitive path returns a file containing a secret.

Missing authentication, IDOR/broken access control, and exposed database rules are deferred:
they need an endpoint model, authenticated identities, or provider-specific discovery.

**If we do not build this:** P1 and P2 are infrastructure with no product result, and the
proof discipline is never exercised against a real app.

**What we are choosing not to build:** authenticated/IDOR checks, live URL probing, intensity
levels 1–2, write-based confirmation, signed proof bundles (P5), and reports (P6).

## Goals & Success Metrics

1. **Reproduce, don't guess.** Every `EXPOSED` has a saved request/response pair and a short
   evidence string; a signature alone is not a verdict.
2. **No false `EXPOSED` on the safe fixture.** The safe app returns `NOT_REPRODUCED` for all
   three probes and exits 0.
3. **Keep the sandbox closed.** The app and the probe sidecar have no egress; the host reaches
   neither over a published port.
4. **Minimize data.** Capture at most 4 KiB of body per response; redact secret values; no
   bulk downloads.
5. **Clean up every time.** No container, sidecar, network, or workspace remains on success,
   failure, timeout, or interrupt.

Success metrics:

- Vulnerable fixture: 3 `EXPOSED`, each with a matching request/response and evidence.
- Safe fixture: 0 `EXPOSED`, 3 `NOT_REPRODUCED`, exit 0.
- Egress test: an external request from the app or sidecar fails.
- Default `uv run pytest` makes zero Docker calls; the Docker suite passes with
  `PRY_DOCKER_TESTS=1`.
- Host repo tree hash is unchanged before/after a local scan.

## User Personas & Scenarios

**App owner.** Runs `pry scan ./my-app`. Pry boots the app in the sandbox, runs the three
floor probes, prints the evidence, writes `results.json` beside the P2 snapshot, and cleans
up. No ownership token is needed for a local path: the user already has the files.

**Maintainer.** Adds a probe. The probe receives a base URL inside the sandbox and returns a
structured result; it cannot reach the host or the internet.

**Scenario:**

```bash
pry scan ./my-app
# CORS with credentials      EXPOSED
# Verbose error leakage      NOT_REPRODUCED
# Exposed secret files       EXPOSED
# Results: ~/.pry/runs/<id>/results.json
# exit 1 (at least one EXPOSED)
```

## Requirements

### Must-have

| ID | Requirement |
|---|---|
| M1 | **Local scan command.** `pry scan PATH` where PATH is an existing directory: run P2 intake, probes, results, cleanup. No P1 token for a local path. URLs keep the existing P1 gate and remain `UNVERIFIED` until live probing exists. |
| M2 | **Sandbox transport.** P2's `--network=none` run is replaced by a per-run Docker `--internal` network. The app joins it with the alias `app`; a Python probe sidecar joins the same network. The host executes probes via `docker exec` into the sidecar. Neither container has egress or a published host port. |
| M3 | **CORS probe.** One `GET /` with `Origin: https://pry.invalid`. `EXPOSED` iff the response reflects that exact origin in `Access-Control-Allow-Origin` and sets `Access-Control-Allow-Credentials: true`. `*` plus credentials is `NOT_REPRODUCED` (browsers reject it). |
| M4 | **Verbose error probe.** One `GET /__pry_missing__?id=%27`. `EXPOSED` iff the response is 4xx/5xx and contains a strong stack-trace, framework-debug, or SQL-error signature. A generic 404 page is `NOT_REPRODUCED`. |
| M5 | **Exposed secret probe.** `GET` a fixed list: `/.env`, `/.git/config`, `/.git/HEAD`, `/config.json`, `/.aws/credentials`, `/backup.sql`. `EXPOSED` iff a 200 response contains a secret signature (key name plus a value). A 200 with no secret, a 404, or a redirect to another origin is `NOT_REPRODUCED`. Values are redacted. |
| M6 | **Result contract.** Each probe returns `probe`, `verdict` (`EXPOSED`/`NOT_REPRODUCED`/`UNVERIFIED`), `cause`, `evidence`, `request` (method, url, headers), and `response` (status, headers, capped body excerpt). Write `results.json` (0600) with a summary beside the P2 snapshot. |
| M7 | **Verdict discipline.** No `EXPOSED` without a captured pair. No `SAFE`/`SECURE` anywhere. A network/transport failure is `UNVERIFIED`, not `NOT_REPRODUCED`. |
| M8 | **Data minimization and redaction.** Cap each body excerpt at 4 KiB. For secret files, redact values (`[redacted]`) and keep only the key name and a short context. No response body is uploaded. |
| M9 | **Cleanup.** Remove the sidecar, app, internal network, and workspace on success, failure, timeout, and SIGINT. The run dir with the snapshot and results remains. |
| M10 | **CLI output and exit codes.** Human summary plus `--json` (full result object). Exit 0 for no `EXPOSED`, 1 for any `EXPOSED`, 2 for usage/ownership/sandbox errors. Only level 0 is accepted. |
| M11 | **Offline tests.** Probe decision logic, redaction, result schema, CLI, and cleanup are tested with fakes. No Docker in the default suite. |
| M12 | **Opt-in Docker tests.** Vulnerable and safe fixtures; assert `EXPOSED`/`NOT_REPRODUCED`, egress blocked, host unchanged, cleanup. `PRY_DOCKER_TESTS=1`. |
| M13 | **Ethics gate.** `ETHICS.md` is approved and in the tree before probe code lands. The README and CLAUDE status reference it. |
| M14 | **Docs truth.** README, `CLAUDE.md`, architecture, roadmap, and capability roadmap state P3's actual slice; the deferred checks and live probing are named; no probe claim beyond the code. |

### Should-have

| ID | Requirement |
|---|---|
| S1 | A `--only PROBE` filter for debugging one probe (`cors`, `errors`, `secrets`). |
| S2 | Per-probe timing in the result. |
| S3 | The run dir includes a raw (unredacted) local proof file at 0600, separate from the redacted `results.json`. P5 will own signing/replay. |

### Nice-to-have (not this change)

Missing auth, IDOR, DB rules, header-only findings, live URL probing, level 1–2, P5 signed
bundles, P6 reports.

## Technical Considerations

**Pipeline fit.** P3 consumes P2's snapshot and sandbox. It does not bypass P1: local paths
are owned by possession; URLs still require a token. The scan path is:
`local path -> intake -> internal network + app + sidecar -> probes -> results -> cleanup`.

**Network change.** P2 currently starts the app with `--network=none`, which prevents any
probe from the host. P3 creates a per-run `--internal` network:

- app container: `--network=<network> --network-alias=app`; no egress; no `-p`.
- sidecar: same network, no alias needed; `--network=<network>`; no egress.
- host: `docker exec <sidecar> python /pry/sidecar.py <probe> <base-url>`.
- the sidecar image is `python:3.9-slim`; the probe script is mounted read-only from Pry's
  own source. It uses only the standard library.
- P2's readiness still uses `docker exec` into the app; the sidecar starts after readiness.

The internal network has no gateway to the internet. Docker's `--internal` flag is the
boundary; the tests assert it and the egress fixture proves it.

**Probe logic.** The sidecar contains the three probes and prints a JSON `ProbeResult` for
each. The host never sends target-controlled data back into the sidecar beyond the base URL
and probe name. Redirects are not followed across origins. Timeouts are short (5 s per
request) and the body read is capped at 4 KiB.

**Verdict rules.**

- CORS: reflect + credentials = `EXPOSED`; `*` + credentials = `NOT_REPRODUCED`; no ACAO =
  `NOT_REPRODUCED`; transport failure = `UNVERIFIED`.
- Errors: strong signature + 4xx/5xx = `EXPOSED`; generic body = `NOT_REPRODUCED`.
- Secrets: 200 + secret signature at a sensitive path = `EXPOSED`; value redacted. 200 without
  a signature, 404, or cross-origin redirect = `NOT_REPRODUCED`.

**Result schema.** `version`, `target` (snapshot id/path/kind), `results` (list), `summary`
(counts), `created_at`. Each request/response is a dict with headers normalized to lowercase.
`results.json` is 0600 in the run dir; the snapshot and results are linked by `sandbox_id`.

**CLI.** `pry scan PATH` detects a directory and routes to the local path; the current URL
path is unchanged. `--json` prints the full result. The existing `--token`/`--token-file`
flags are ignored for local paths but still required for URLs. `--level` other than 0 exits 2.

**Why a sidecar.** Running probes inside the app container would tie them to the app's
runtime and image; a sidecar gives one Python probe environment for static and Node targets,
keeps the app image untouched, and preserves no-egress. The cost is one more container and a
network change.

## Risks & Open Questions

| Risk | Severity | Mitigation |
|---|---|---|
| **False `EXPOSED`** from a generic 404 containing a stack-trace word, or a secret-like placeholder. | Med/High | Conservative signatures, require 4xx/5xx for errors, require a key/value shape for secrets, safe-fixture tests. |
| **False `NOT_REPRODUCED`** when the app's CORS only appears on an API route, not `/`. | Med/Med | First slice probes `/` only; document the limit; endpoint discovery is future work. |
| **CORS severity** — reflect + credentials is exploitable, but only if a sensitive endpoint is reachable from a browser. | Med/Med | Report the exact pair; do not claim data theft; the owner decides impact. |
| **Probe side effect** — even a GET can trigger a webhook or a cache write. | Med/High | One GET per probe, no auth, no query that mutates; document the method; sandbox only. |
| **Secrets in results/logs.** | Med/High | Redact values, cap bodies, 0600, local only; raw proof separate (S3) and future P5 redaction. |
| **Internal-network complexity / Docker differences.** | Med/Med | Integration tests on macOS; assert `--internal`, no `-p`, no gateway; document. |
| **Docker shared kernel.** | Med/High | Same caveat as P2; ETHICS.md states it plainly. |

Open questions:

- Should the secret probe also try the app's framework-specific paths (Next `.env.local`,
  Supabase config)? Defer; fixed list first.
- Should a CORS misconfig without credentials be reported as a non-verdict observation? Not
  in this slice; no `EXPOSED`, and the verdict contract has no hardening state.
- Should `--json` include the raw unredacted proof? No; S3 keeps it local and separate.

**The hard question before greenlighting:** CORS reflection with credentials is a real
misconfiguration, but its impact depends on an endpoint that returns sensitive data. Is
reporting the header pair as `EXPOSED` overclaiming, or is the reproduced misconfiguration
itself the finding? This PRD treats the reproduced header pair as the finding and says
exactly what was observed; it does not claim data was stolen.

## Out of Scope

- Missing authentication, IDOR/broken access control, exposed database/open rules.
- Security-header-only findings (not an exploit).
- Live URL intake/probing, levels 1–2, write-based confirmation.
- Signed/replayable proof bundles (P5), corpus/report (P6), platform integration (P7).
- Authenticated scanning, credential handling, endpoint discovery.
- Any claim that a clean result means secure.

## Acceptance Tests

| ID | Test | Expected |
|---|---|---|
| AT1 | Vulnerable fixture `/` with reflected origin + credentials | `EXPOSED`, pair shows ACAO/ACAC |
| AT2 | Safe fixture / `*` without credentials | `NOT_REPRODUCED` |
| AT3 | Safe fixture generic 404 | `NOT_REPRODUCED` |
| AT4 | Vulnerable fixture stack trace / SQL error page | `EXPOSED` with the matched excerpt |
| AT5 | Vulnerable fixture `/.env` with a fake secret | `EXPOSED`, value redacted |
| AT6 | Safe fixture `/.env` 404 | `NOT_REPRODUCED` |
| AT7 | Safe fixture full scan | 0 `EXPOSED`, exit 0 |
| AT8 | Vulnerable fixture full scan | 3 `EXPOSED`, exit 1 |
| AT9 | App and sidecar egress | external request fails |
| AT10 | Cleanup after success/failure/SIGINT | no container/network/workspace |
| AT11 | Host repo after scan | tree hash unchanged |
| AT12 | Default suite | offline; Docker tests skipped |
| AT13 | `results.json` schema and redaction | version/target/results/summary; no secret value |
| AT14 | URL scan unchanged | requires P1 token; `UNVERIFIED` |
| AT15 | Docs | ETHICS/README/CLAUDE/architecture/roadmap accurate; no overclaim |

## Self-Critique

- 🟡 **CORS impact is contextual.** The header pair is reproducible, but the data exposure
  depends on an endpoint. The result must say "misconfiguration reproduced," not "data
  stolen."
- 🟡 **Three probes are a narrow floor.** Missing auth/IDOR/DB rules are deferred; the README
  must say so.
- 🟡 **The sidecar changes P2's network model.** It is the right architecture, but it touches
  P2 tests and docs; budget for that.
- 🟢 **Every verdict is tied to a saved request/response**, and the safe fixture is a hard
  gate against false `EXPOSED`.
