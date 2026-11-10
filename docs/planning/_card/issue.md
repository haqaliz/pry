# Live Rate-Limit Observation (P4 remainder)

- **Type:** feat
- **Slug:** `live-rate-limit`
- **Owner:** aliz
- **Source:** inline brief. No GitHub issue.
- **Capability:** P4 — bounded live rate-limit observation.

## Brief

The local rate-limit observation exists; the live path rejects all level 1 checks. A bounded
live sample is useful for the app owner, but it carries load and lockout risk. This slice allows
it only with an explicit per-target `--confirm`, a hard cap of 5 GETs, 0.5s spacing, and an
immediate stop on the first 429/503/`Retry-After`. It is an unsigned hardening observation,
never `EXPOSED`, never a proof, and never changes the exit code.

## Flow

```bash
pry scan https://example.com --token <token> \
  --level 1 --confirm --rate-limit-endpoint /login --rate-limit-count 3
```

One declared path, no auth, GET only. Local behavior and the 1–20 local cap are unchanged.

## Scope

- Live `--level 1` allowed only with `--confirm` and `--rate-limit-endpoint`.
- Live cap 5, default 5; spacing 0.5s; stop on 429/503/`Retry-After`.
- Observation in `results.json`, CLI/JSON, report; no proof, no verdict.
- P1 token is validated before any request.
- Live SSRF stays rejected; IDOR still works at level 0.
- Tests: validation, live scan, CLI gating, no-proof/exit-neutral.
- Docs/ETHICS: bounded live sample policy and risk.

## Out of scope

- Live SSRF, Level 2 writes, IDOR discovery, provider DB rules, hosted reports.
- Load testing, concurrency, credential use.
- Treating a missing limit as `EXPOSED`.

## Acceptance criteria

- Live level 1 + confirm + endpoint → one `rate_limit` observation.
- 429/503/Retry-After → `THROTTLED`, stop immediately.
- Count 6 → exit 2 before any request; default 5.
- Missing `--confirm` or endpoint → exit 2 before any request.
- SSRF flags on a URL → exit 2 before any request.
- No verification/proof; exit code unchanged by the observation.
- No "secure" claim; docs state the load/lockout risk.
