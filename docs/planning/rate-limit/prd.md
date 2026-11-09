# PRD — Rate-Limit Observation (P4 Level 1, local)

- **Status:** Draft, awaiting review gate
- **Owner:** aliz
- **Slug:** `rate-limit`
- **Capability:** P4 Level 1, local rate-limit observation

## Problem Statement

Rate limiting is a hardening control. "No rate limit observed" is not a reproduced
request/response pair showing data exposure, so it cannot honestly be an `EXPOSED` verdict
under Pry's contract. The useful, honest output is a separate observation: "N declared
requests were accepted without throttling," or "throttling began at request K."

This slice adds that observation for a local sandbox endpoint only. It does not create a new
verdict, a proof bundle, or a live scan.

## Goals & Success Metrics

1. Bounded local probe: 1–20 sequential GETs to a declared path, Level 1 + `--confirm`.
2. All 2xx → `OBSERVED`; any 429/503/`Retry-After` → `THROTTLED`; transport failure →
   `UNVERIFIED`.
3. Observations appear in `results.json`, the CLI/JSON output, and a report section; they are
   never `EXPOSED` and never signed.
4. Level 1 may run SSRF and/or rate-limit; at least one is required.
5. No live rate-limit probing, no Level 2, no writes.

## Requirements

| ID | Requirement |
|---|---|
| M1 | CLI: `pry scan PATH --level 1 --confirm --rate-limit-endpoint PATH --rate-limit-count N`. N 1–20, default 10. |
| M2 | Local only; a URL + rate-limit flags, level 0, or level 2 → exit 2. Missing `--confirm` → exit 2 `CONFIRMATION_REQUIRED`. |
| M3 | Level 1 with neither SSRF nor rate-limit config → exit 2 `LEVEL1_CHECK_REQUIRED`. Both may run. |
| M4 | Endpoint path-only, no query/fragment; invalid → exit 2 `RATE_LIMIT_CONFIG_INVALID`, no request. |
| M5 | Probe: sequential GETs, no auth/cookies, 0.1s spacing, 10s per request; record statuses and any `Retry-After`. |
| M6 | `THROTTLED` on 429/503/`Retry-After`; `OBSERVED` if all 2xx; `UNVERIFIED` on transport/control failure. |
| M7 | Observation object: probe `rate_limit`, status, endpoint, count, statuses, evidence, first/last request/response; no verdict, no proof. |
| M8 | `ScanResult.observations`; `results.json`; report "Observations" section; CLI human/JSON; exit code unaffected. |
| M9 | Tests: sidecar/scan/CLI/report; Docker fixture with a throttled and an unthrottled endpoint; no third-party. |
| M10 | Docs/ETHICS: hardening observation, local sandbox, bounded count, confirmation, live rate-limit deferred, no secure. |

## Technical Considerations

- Add `probe_rate_limit(base_url, path, count, fetch=None)` to `sidecar.py`; it returns a JSON
  observation. The probe sidecar already runs on the internal network; no new sidecar.
- `ProbeClient.run_rate_limit(path, count)` execs
  `python /pry/sidecar.py rate_limit BASE_URL PATH COUNT` and parses the observation.
- `ScanOutcome`/`ScanResult` gain `observations`; `finalize_results` writes them alongside
  `results`/`summary`. Proof signing remains EXPOSED-only.
- The report loader/renderer adds observations; every dynamic value is escaped.
- The rate-limit observation is not in the corpus signing/proof path; it may be added to the
  corpus as a separate record later. This slice stores it in the run/report.
- 429/503 at request K is `THROTTLED`; `Retry-After` is captured but not interpreted.
- The probe does not authenticate and does not send a body. It is a load test only in the
  narrow sense of N bounded GETs; live targets are refused.

## Risks & Open Questions

| Risk | Severity | Mitigation |
|---|---|---|
| **Load/lockout** on a live app. | High/High | Local sandbox only; N ≤ 20; 0.1s spacing; no live. |
| **`OBSERVED` read as "vulnerable" or `EXPOSED`.** | High/High | Separate observation section; no proof; no verdict; exact wording. |
| **False `OBSERVED`** because the limit is below N or keyed by account. | Med/Med | Say "no throttling seen in N declared requests"; not a global claim. |
| **False `THROTTLED`** from a generic 503 outage. | Med/Med | Record status/`Retry-After`; the observation quotes it. |
| **Level 1 config matrix confusion.** | Med/Med | At least one of SSRF/rate-limit; both allowed; clear causes. |
| **Observation schema drift.** | Low/Med | One dataclass, report/CLI tests. |

**Hard question:** if the app accepts 20 requests, is that a finding? It is a hardening
observation, not a reproduced data exposure. The product should say so and not inflate it into
`EXPOSED`.

## Out of Scope

- Live rate-limit probing, distributed/parallel requests, credential/keyed limits.
- Treating missing rate limiting as `EXPOSED`.
- Level 2/writes, auth, discovery, DB rules, hosted reports.

## Acceptance Tests

| ID | Test | Expected |
|---|---|---|
| AT1 | All 2xx in N requests | `OBSERVED`; no proof; report section |
| AT2 | 429 at request K | `THROTTLED`, K recorded |
| AT3 | Transport error | `UNVERIFIED` |
| AT4 | Missing `--confirm` / level 0 / URL / N out of bounds | exit 2, no request |
| AT5 | Level 1 with neither SSRF nor rate-limit | exit 2 |
| AT6 | SSRF + rate-limit together | both run, observations separate |
| AT7 | Report/CLI/JSON | observations shown; counts/exit unchanged |
| AT8 | Docker throttled/unthrottled fixtures | THROTTLED/OBSERVED; cleanup |
| AT9 | Default suite | offline; Docker opt-in |
| AT10 | Docs | hardening, local, bounded, no secure, no EXPOSED |

## Self-Critique

- 🟡 **This is not a moat finding.** It is a hardening observation, and the report must not
  dress it up as an exposure.
- 🟡 **N is a sample, not proof of absence.** "No throttling seen in N requests" is the
  honest ceiling.
- 🟢 **The bounded local probe is safe to run** and gives the owner useful signal without a
  live load test.
