# PRD — Response Header Observations (P3 remainder)

- **Status:** Approved on standing instruction (2026-11-11)
- **Owner:** aliz
- **Slug:** `header-observations`
- **Capability:** P3 remainder — missing security headers, observation only

## Problem Statement

The floor list includes missing security headers. A missing header is a hardening gap, not a
reproduced exploit, so it cannot be `EXPOSED` under the verdict contract. The honest output is
an unsigned observation: "these recommended headers were missing on `/`." A present header is
not proof of security, and a missing one is not proof of exploitability.

## Requirements

| ID | Requirement |
|---|---|
| M1 | `--headers` opt-in on local and live scans; one GET `/`; no level/confirmation. |
| M2 | Recommended: CSP, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy, COOP; HSTS only for HTTPS. |
| M3 | `OBSERVED` with lowercased `missing`/`present` lists and evidence; `UNVERIFIED` on transport. |
| M4 | Observation in `results.json`, CLI/JSON, report; no proof, no verdict, no exit change. |
| M5 | Local uses the probe sidecar; live uses the same function in-process after the P1 gate. |
| M6 | No `--headers` → observations unchanged. |
| M7 | Tests: sidecar/parser/client/scan/CLI/report; Docker fixtures for missing/present. |
| M8 | Docs: hardening observation, not a verdict; no secure; no graded severity. |

## Technical Considerations

- `probe_headers(base_url, fetch=None)` in `sidecar.py`; returns the observation dict.
- `headers.py`: `HEADER_NAME`, `RECOMMENDED_HEADERS`, `parse_headers_result(payload)`.
- `ProbeClient.run_headers()` execs `python /pry/sidecar.py headers BASE_URL`.
- `scan_local(..., headers=False)` / `scan_live(..., headers=False)` append the observation and
  pass it to `finalize_results`.
- CLI `--headers`; local/live; no token changes.
- The report already has an Observations section; add missing/present display.
- No new dependencies; one GET; body capped; no credentials.

## Risks

| Risk | Severity | Mitigation |
|---|---|---|
| **Header presence read as "secure".** | High/High | Observation wording; no proof; no verdict; docs. |
| **Missing header read as `EXPOSED`.** | High/High | Separate observation; never in results/verdicts. |
| **Header check on a live target** adds a request. | Low/Low | One GET; P1 token; no confirmation. |
| **CSP/frame-ancestors overlap.** | Low/Med | Report both names; no policy grading. |
| **CDN/proxy headers differ from app headers.** | Med/Med | Observation quotes the response; no global claim. |

## Out of Scope

- Grading/severity, CSP parsing, cookie flags, TLS grading, hosted reports, EXPOSED.

## Acceptance Tests

| ID | Test | Expected |
|---|---|---|
| AT1 | Local `--headers` | OBSERVED with missing/present |
| AT2 | Live `--headers` | OBSERVED, P1 gate first |
| AT3 | Transport failure | UNVERIFIED |
| AT4 | No `--headers` | observations unchanged |
| AT5 | Observation | no proof/EXPOSED; exit unchanged |
| AT6 | Report | escaped missing/present |
| AT7 | Docker | missing/present fixtures; cleanup |
| AT8 | Default suite | offline; Docker opt-in |

## Self-Critique

- 🟡 **This is hygiene, not a moat finding.** Say so in the report and docs.
- 🟡 **Headers can be set by a CDN/proxy**, not the app; quote the response, not a global claim.
- 🟢 **It completes the P3 header item without stretching the verdict contract.**
