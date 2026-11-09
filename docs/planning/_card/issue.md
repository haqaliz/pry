# Rate-Limit Observation (P4 Level 1, local)

- **Type:** feat
- **Slug:** `rate-limit`
- **Owner:** aliz
- **Source:** inline brief. No GitHub issue.
- **Capability:** P4 Level 1 rate-limit observation, local only.

## Brief

Send a bounded series of GETs to a declared endpoint in the local sandbox and record whether
the app throttles. This is a **hardening observation**, not an `EXPOSED` verdict: absence of a
rate limit is not a reproduced request/response pair demonstrating data exposure. The report
gets an Observations section; the verdict counts and signed proof bundles stay reserved for
`EXPOSED`.

## Flow

```bash
pry scan ./my-app --level 1 --confirm \
  --rate-limit-endpoint /login --rate-limit-count 10
```

- 429/503/`Retry-After` at any request → `THROTTLED`.
- All 2xx in the bounded series → `OBSERVED` ("no throttling seen in N requests").
- Transport/control failure → `UNVERIFIED`.
- No `EXPOSED` from this check; no proof bundle; exit code stays based on verdicts.

## Scope

- Level 1 + `--confirm`, local only; path-only endpoint; count 1–20 (default 10).
- Sequential GETs, no auth, 0.1s spacing, bounded total time; no POST/body.
- Observation in `results.json` and the HTML report; CLI/JSON output.
- Level 1 may run SSRF and/or rate-limit; at least one is required.
- Tests: sidecar/scan/CLI/report; Docker fixture with a throttled and an unthrottled endpoint.

## Out of scope

- Live rate-limit probing (load/lockout risk).
- Treating "no rate limit" as `EXPOSED`.
- Level 2/writes, auth, distributed/parallel probing, discovery.
- Hosted reports.

## Acceptance criteria

- All 2xx in N requests → `OBSERVED`, report shows it, no proof bundle, exit 0/1 unchanged.
- A 429/503 at request K → `THROTTLED` with K and status.
- Transport error → `UNVERIFIED`.
- Missing `--confirm`, level 0, URL, or count out of bounds → exit 2.
- Level 1 with neither SSRF nor rate-limit config → exit 2.
- Observations never appear as `EXPOSED` or as signed proof bundles.
- Default suite offline; Docker test opt-in.
- No "secure" claim.
