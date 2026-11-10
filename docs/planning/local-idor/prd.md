# PRD — Local IDOR (P3 remainder)

- **Status:** Merged to `master` (2026-11-11). Configured local IDOR implemented; IDOR
  discovery, exposed database rules, live SSRF, Level 2, and hosted reports are deferred.
- **Owner:** aliz
- **Slug:** `local-idor`
- **Capability:** P3 remainder — configured local IDOR/access control

## Problem Statement

Live IDOR is implemented, but the safe sandbox path is missing the companion check. The
floor suite already covers missing auth locally; IDOR is the access-control check where
identity A can read identity B's object. Running it locally keeps testing on the sandbox,
with the credential config mounted read-only and never stored in results.

## Goals & Success Metrics

1. `pry scan ./app --idor-config idor.json` runs A→A, B→B, and A→B inside the sandbox.
2. `EXPOSED` only when both controls pass and A→B returns 2xx JSON; signed and reportable.
3. Config 0600; temp copy 0600; read-only mount; removed on every path.
4. Credentials, config path, and temp path never appear in results/proofs/reports/logs/errors.
5. No config → existing local scan unchanged.

## Requirements

| ID | Requirement |
|---|---|
| M1 | Local `--idor-config FILE` at level 0; no `--confirm`; config 0600 and validated by the existing `load_idor_config`. |
| M2 | Write a 0600 JSON temp copy; mount read-only at `/pry-config/idor.json` in the probe sidecar; remove after the probe. |
| M3 | Sidecar `idor` mode reads the config, sends the three GETs, and returns a `ProbeResult`-shaped dict with redacted auth/cookie headers. |
| M4 | Host parses to `ProbeResult`; EXPOSED signed; NOT_REPRODUCED/UNVERIFIED as live IDOR. |
| M5 | Local path with `--idor-config` no longer returns `IDOR_REQUIRES_LIVE`; URL behavior unchanged. |
| M6 | No config → no IDOR result; floor/SSRF/rate-limit unchanged. |
| M7 | Tests: sidecar mode, config mount, scan, CLI, Docker fixture with two identities/objects. |
| M8 | Docs: local IDOR, 0600, read-only mount, redaction, no discovery, no secure. |

## Technical Considerations

- Move the IDOR probe core into a sidecar-callable function (stdlib only) and keep the live
  path calling it; the live and local checks must not drift.
- `DockerRunner.start_sidecar(..., config_path=None)` adds
  `-v <config_path>:/pry-config/idor.json:ro`. The rest of the sandbox flags are unchanged.
- `ProbeClient.run_idor()` execs `python /pry/sidecar.py idor BASE_URL /pry-config/idor.json`.
- `scan_local` creates the temp config with `mkstemp`, `fchmod 0600`, writes the JSON, passes
  the path to the sidecar, and removes it in `finally`. The original config path is not stored.
- The sidecar result redacts `Cookie`, `Authorization`, `Set-Cookie`, and API-key values; the
  host `ProbeResult` normalizes again.
- The config mount is read-only; the sidecar has no egress; no host port.

## Risks & Open Questions

| Risk | Severity | Mitigation |
|---|---|---|
| **Credential leakage** via castore/argv/logs/output. | High/High | 0600, read-only mount, sidecar redaction, leak tests, no config/temp path in outputs. |
| **Temp config left behind.** | Med/High | `finally` cleanup; tests. |
| **Config file symlink/permissions.** | Med/Med | Existing loader refuses non-0600; temp uses mkstemp/fchmod. |
| **Probe drift between live/local.** | Med/Med | Shared sidecar function; live tests. |
| **False EXPOSED** from public object. | Med/Med | Both controls must pass; wording quotes the declared pair. |
| **Local IDOR with no config** silently skipped. | Low/Med | No config → no result; docs. |

**Hard question:** the sandbox credentials prove the configured pair, not a global IDOR
sweep. The result must say "declared pair" and not generalize.

## Out of Scope

- IDOR discovery, non-configured sweeps, live changes, DB rules, level 2/writes, hosted reports.

## Acceptance Tests

| ID | Test | Expected |
|---|---|---|
| AT1 | Local config + A→B 200 | EXPOSED, signed, report |
| AT2 | A→B 403 | NOT_REPRODUCED |
| AT3 | B→B 403 | UNVERIFIED control failed |
| AT4 | Config 0644/invalid/absolute paths | exit 2, no scan |
| AT5 | No config | existing results, no IDOR |
| AT6 | Temp config removed | absent after success/failure |
| AT7 | Credentials/config path leak | absent from outputs |
| AT8 | Docker fixture | two identities/objects, EXPOSED, cleanup |
| AT9 | Default suite | offline; Docker opt-in |
| AT10 | Docs | local, 0600, redaction, no discovery, no secure |

## Self-Critique

- 🟡 **Credential handling is the critical surface.** Read-only mount + 0600 + cleanup +
  redaction + leak tests.
- 🟡 **The check is one declared pair.** Not a global IDOR claim.
- 🟢 **A real cross-request with both controls is a reproduced access-control failure.**
