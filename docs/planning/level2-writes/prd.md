# PRD — Local Level 2 Write Confirmation (P4 remainder)

- **Status:** Merged to `master` (2026-11-11). Local Level 2 write confirmation implemented;
  live writes, live SSRF, provider database/open-rule checks, and hosted reports are deferred.
- **Owner:** aliz
- **Slug:** `level2-writes`
- **Capability:** P4 — write-based confirmation, local sandbox slice

## Problem Statement

A missing auth check on a write is more serious than a read leak, and a 200 on a write is not
proof that the write landed. The honest check is a declared unauthenticated write followed by a
declared read that shows the unique value Pry wrote. It must run only against the disposable
local sandbox; a live write can alter real data.

## Goals & Success Metrics

1. `pry scan ./app --level 2 --confirm --write-config write.json` reproduces the write and
   captures both the write and verification pairs.
2. `EXPOSED` only when the write is 2xx and the verification GET is 2xx and contains the
   generated marker; signed and reportable.
3. A rejected write or an absent marker is `NOT_REPRODUCED`; transport/write 5xx is `UNVERIFIED`.
4. Live writes are rejected before any request.
5. The config is 0600, mounted read-only, and removed; no config path or body secrets leak.

## Requirements

| ID | Requirement |
|---|---|
| M1 | Local `--level 2 --confirm --write-config FILE`; live URL exits 2 before any request. |
| M2 | Config 0600 JSON: `method` POST/PUT/PATCH, path-only `endpoint`, `body` containing `{{marker}}`, path-only `verify_endpoint`, optional `verify_contains`, optional `content_type`. |
| M3 | Generate `pry-<hex>`, substitute in body and verification, send the write with no auth/cookies, then GET the verification path. |
| M4 | `EXPOSED` only for write 2xx + verify 2xx + marker in the verify body; sign the proof; nest the verification pair under `response.verification`. |
| M5 | 401/403/404 write or missing marker → `NOT_REPRODUCED`; write 5xx/transport or verify transport → `UNVERIFIED`. |
| M6 | Temp config 0600, read-only mount at `/pry-config/write.json`, removed in `finally`. |
| M7 | Tests: config, sidecar, client, scan, CLI, Docker fixture; no live request. |
| M8 | Docs: local-only, marker, proof shape, live writes deferred, no secure. |

## Technical Considerations

- `write.py`: `WriteConfig`, `load_write_config`, `validate_write_config`,
  `parse_write_result`; marker substitution happens in the sidecar.
- `sidecar.py`: `probe_write(base_url, config, fetch=None)`; `write` main branch.
- `intake/docker.py`: `start_sidecar(..., write_config_path=None)` mounts the 0600 temp file
  read-only at `/pry-config/write.json`.
- `scan.py`: `write_config=None`; write a 0600 temp config, start the sidecar with both config
  mounts, run write after IDOR; remove temps in `finally`.
- `client.py`: `run_write()` execs the sidecar.
- `cli.py`: `--write-config`; level 2 requires `--confirm`; live rejects it.
- No new dependencies; body capped at 4 KiB; no credentials.

## Risks

| Risk | Severity | Mitigation |
|---|---|---|
| **Live write alters real data.** | High/Critical | Local-only; URL + write config exits 2 before any request. |
| **False `EXPOSED` from a static marker.** | High/High | Unique per-run marker must appear in the body and the verification read; both requests captured. |
| **Write succeeds but verification is weak.** | Med/High | The owner declares the verification path; absence is `NOT_REPRODUCED`, not EXPOSED. |
| **Secrets in the declared body.** | Med/High | Config 0600; local-only; docs say use test data, not real secrets; stored body is capped. |
| **Config path/temp path leak.** | Med/Med | 0600 temp, read-only mount, cleanup, leak tests. |
| **The verification endpoint is cached/public.** | Med/Med | The marker is unique; a public verification path still proves the write is readable, but the evidence quotes the response. |

**Hard question:** a 2xx write plus a marker in a read is strong, but the marker could be stored
in a place the app exposes for other reasons. The unique per-run value makes a pre-existing
marker implausible; the result says exactly what was written and read.

## Out of Scope

- Live writes, DELETE, file uploads, auth, multi-step workflows.
- IDOR discovery, provider DB rules, live SSRF, hosted reports.
- Discovery of write endpoints.

## Acceptance Tests

| ID | Test | Expected |
|---|---|---|
| AT1 | POST 201 + GET 200 marker | EXPOSED, signed, report |
| AT2 | Write 401/403/404 | NOT_REPRODUCED |
| AT3 | Write 2xx, marker absent | NOT_REPRODUCED |
| AT4 | Write 5xx/transport | UNVERIFIED |
| AT5 | Level 2 without confirm/config | exit 2, no scan |
| AT6 | Config 0644/missing/invalid/absolute path | exit 2, no scan |
| AT7 | Live URL + write config | exit 2, no request |
| AT8 | Temp config removed; path absent from outputs | pass |
| AT9 | Docker fixture | write + verify, proof, cleanup |
| AT10 | Docs | local-only, live deferred, no secure |

## Self-Critique

- 🟡 **Writes are dangerous.** The local sandbox and the live rejection are the guardrails.
- 🟡 **The verification path is owner-declared.** A weak verifier yields `NOT_REPRODUCED`, not
  a false `EXPOSED`.
- 🟢 **The request pair and the verification pair are both captured and signed.**
