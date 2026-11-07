# PRD — Configured IDOR Checks (Live)

- **Status:** Approved on standing instruction (2026-11-08)
- **Owner:** aliz
- **Slug:** `idor-live`
- **Capability:** P3 remainder — IDOR/access control, live configured slice

## Problem Statement

The missing-auth check proves a declared endpoint returns data without credentials. IDOR is
the companion: a user allowed to see object A must not be able to see object B. This slice
uses a local config with two identities and two object paths, runs three read-only GETs on a
live target the user has proven they own, and reports `EXPOSED` only when identity A reads
object B while both controls succeed.

No discovery, no local IDOR, no writes. The config contains session cookies/tokens, so it
must be 0600 and must never appear in results, proofs, reports, logs, or errors.

## Goals & Success Metrics

1. A→A 200, B→B 200, A→B 200 JSON → `EXPOSED`, signed, report written.
2. A→B 401/403/404 → `NOT_REPRODUCED`.
3. B→B control fails → `UNVERIFIED`; no exposure claim.
4. Invalid config (0644, absolute path, header injection) → exit 2, no request.
5. Credentials and the config path never appear in outputs.
6. Default suite offline; loopback integration only.

## Requirements

| ID | Requirement |
|---|---|
| M1 | Config JSON: `identity_a`/`identity_b` each `{headers: {name: value}}`, `object_a`/`object_b` path-only. File 0600; group/other bits refused. |
| M2 | Validate headers: non-empty names/values, no control chars/newlines, reject `Host`, `Content-Length`, `Transfer-Encoding`; value cap 4096. |
| M3 | Probe: control A (`object_a` with A), control B (`object_b` with B), cross (`object_b` with A). Any control not 2xx JSON/non-empty → `UNVERIFIED` `IDOR_CONTROL_FAILED`. |
| M4 | Cross 2xx JSON/non-empty → `EXPOSED`; 401/403/404 → `NOT_REPRODUCED`; 5xx/transport → `UNVERIFIED`. |
| M5 | Redact `Cookie`, `Authorization`, `Set-Cookie`, `X-Api-Key`, `Proxy-Authorization` values in the stored result; keep header names. The config path and credentials are never stored. |
| M6 | Live only: `pry scan URL --token TOKEN --idor-config FILE`; local path + flag → exit 2 `IDOR_REQUIRES_LIVE`. |
| M7 | `--report`/`--json` include the IDOR result; EXPOSED signed. |
| M8 | P1 token validated before any target request; no token/credential leak. |
| M9 | Tests: config validation, verdicts/controls, redaction, CLI, loopback integration; no third-party targets; no Docker. |
| M10 | Docs: live-only, config example, 0600, three GETs, no discovery/local IDOR, no secure. |

## Technical Considerations

- New `src/pry/probe/idor.py`: `IdorConfig`, `load_idor_config(path)`, `probe_idor(base_url, config, fetch=None)`.
- Reuse `validate_endpoints` for path-only object checks; reuse `urllib_fetch`/`Response`/`TransportError` from the sidecar for HTTP.
- `scan_live(..., idor_config=None)` appends the IDOR result after the default/unauth probes; the shared `finalize_results` signs/reports it.
- The config is loaded/validated in the CLI before `scan_live`; the dataclass is passed to the scan so the file is read once.
- Redaction applies to request and response headers in the stored `ProbeResult`; the actual requests use the real headers.
- The report's deferred list currently says "IDOR and access-control checks ... not implemented"; change it to "IDOR discovery/local IDOR" so the configured live check is not denied.
- A control failure is `UNVERIFIED`, not `EXPOSED`; the probe does not claim exposure from a broken identity.

## Risks & Open Questions

| Risk | Severity | Mitigation |
|---|---|---|
| **Credential leakage** into results/proofs/report/logs. | High/High | Config 0600; redact auth/cookie headers; never store config path; tests scan outputs for the secret. |
| **False `EXPOSED`** from a public object B. | Med/Med | Controls prove A→A and B→B; the result quotes the paths; the owner declared B as another identity's object. |
| **False `NOT_REPRODUCED`** if B is HTML/login. | Med/Med | Require JSON/non-empty; say when the control failed. |
| **Config permissions** on Windows/other. | Low/Med | Target macOS/Linux; refuse group/other bits; document. |
| **Scope**: only one object pair. | Med/Med | Document; multiple pairs are future work. |
| **Overclaim**: A→B 200 may be a shared/public resource. | High/High | Wording: "identity A received a 2xx JSON response for the object declared as B's"; not a global IDOR claim. |

**Hard question:** is one declared object pair enough to call this IDOR, or does it need a
second object from the same collection to rule out public resources? The controls and the
owner's declaration are the evidence; broader sampling is future work.

## Out of Scope

- Local/sandbox IDOR credential transport; discovery; exposed database rules.
- P4/levels 1–2, writes, hosted reports.
- Claims about objects not in the config.

## Acceptance Tests

| ID | Test | Expected |
|---|---|---|
| AT1 | Config 0644 / absolute path / header injection | exit 2, no request |
| AT2 | A→A, B→B, A→B all 200 JSON | EXPOSED, signed, report |
| AT3 | A→B 403 | NOT_REPRODUCED |
| AT4 | B→B 403 | UNVERIFIED control failed |
| AT5 | Redaction | no Cookie/Authorization value in result/proof/report |
| AT6 | Config path/token leak scan | absent from outputs |
| AT7 | Local path + `--idor-config` | exit 2 |
| AT8 | Loopback integration | EXPOSED, report, no secrets |
| AT9 | Default suite | offline; no Docker |
| AT10 | Docs | live-only, 0600, no discovery/local, no secure |

## Self-Critique

- 🟡 **One pair is a narrow IDOR check.** It proves the declared pair; it does not discover
  other objects. Say so.
- 🟡 **Credential handling is the critical surface.** 0600 + redaction + leak tests.
- 🟢 **The controls prevent a broken identity from producing a false EXPOSED.**
