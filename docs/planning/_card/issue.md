# Floor Probes, For Real (P3)

- **Type:** feat
- **Slug:** `floor-probes-real`
- **Owner:** aliz
- **Source:** inline brief. No GitHub issue for this slug.
- **Capability:** P3 — floor probes. Depends on P1, P2, and `ETHICS.md`.

## Brief

Implement the first read-only floor probes that actually reproduce an issue and save the
request/response pair. This slice covers three mechanical classes: CORS with credentials,
verbose error leakage, and exposed secret files. Missing authentication, IDOR/broken access
control, and exposed database rules need endpoint/identity models and are deferred.

The probes run inside the sandbox. P2's run container uses `--network=none`, so the host
cannot reach the app. P3 replaces that with a per-run Docker `--internal` network, the app
on it with an alias, and a Python probe sidecar on the same network. The host runs probes
via `docker exec` into the sidecar. No host port, no egress.

## Current state

- P1 ownership gate and P2 local intake are merged.
- No `src/pry/probe/` exists.
- `pry scan` requires an ownership token and always reports `UNVERIFIED`.
- `ETHICS.md` is a draft in this branch and must be approved before probe code lands.
- The old `feat-target-intake-aliz` mock is not a dependency.

## Scope

1. `pry scan ./path` for local directories: boot the P2 sandbox, run the probes, write
   results, clean up. No P1 token for local files. URLs keep the P1 gate and remain
   `UNVERIFIED` because live probes are not implemented.
2. Probe sidecar on an internal Docker network; no egress from app or sidecar.
3. Probe 1: CORS with credentials. `EXPOSED` only when the response reflects the attacker
   origin and allows credentials; `*` + credentials is `NOT_REPRODUCED`.
4. Probe 2: verbose error leakage. One safe GET to a random path with a quoted parameter;
   `EXPOSED` only on strong stack-trace/framework/SQL signatures.
5. Probe 3: exposed secret files. Fixed sensitive paths; `EXPOSED` only on a 200 response
   with a secret signature. Redact values; show the key name.
6. Result model with the captured request/response, verdict, and cause; `results.json` in
   the run dir; `--json` CLI output.
7. Offline unit tests with fake sidecar responses; opt-in Docker integration on vulnerable
   and safe fixtures.
8. Update P2 docs/tests for the network-mode change.

## Out of scope

- Missing authentication, IDOR/broken access control, exposed database/open rules.
- Security-header-only findings (not an exploit; no `EXPOSED`).
- Live URL intake/probing, intensity levels 1–2, write-based checks.
- Signed/replayable proof bundles (P5), corpus/report (P6).
- Any claim that a clean result means secure.

## Acceptance criteria (draft)

- Vulnerable fixture: `pry scan` returns `EXPOSED` for all three probes, each with a
  redacted request/response and a matching evidence string.
- Safe fixture: all three return `NOT_REPRODUCED`, exit 0, never `EXPOSED`.
- CORS `*` without credentials → `NOT_REPRODUCED`.
- A generic 404 → `NOT_REPRODUCED`; a stack trace/SQL error → `EXPOSED`.
- A 404 `/.env` → `NOT_REPRODUCED`; a 200 `/.env` with a secret → `EXPOSED`, value redacted.
- App and sidecar have no egress; external requests fail.
- The sandbox, sidecar, network, and workspace are removed on success and failure.
- The host repo is unchanged.
- Default suite offline; Docker tests opt-in with `PRY_DOCKER_TESTS=1`.
- `ETHICS.md` approved before probe code lands.

## Notes

- P3 changes P2's run network from `--network=none` to an `--internal` network so the
  sidecar can reach the app. The app still has no egress. P2 tests/docs must be updated.
- The signed proof bundle is P5; P3 captures a local, redacted, replayable pair.
