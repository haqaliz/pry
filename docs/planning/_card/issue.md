# Response Header Observations (P3 remainder)

- **Type:** feat
- **Slug:** `header-observations`
- **Owner:** aliz
- **Source:** inline brief. No GitHub issue.
- **Capability:** P3 remainder — missing security headers, as an observation.

## Brief

Check the app's root response for a short list of recommended security headers and report what
is missing. This is a **hardening observation**, not an `EXPOSED` verdict: a missing header is
not a reproduced request/response exploit, and a present header does not make the app secure.
The report gets an Observations section; nothing is signed.

## Flow

```bash
pry scan ./my-app --headers
pry scan https://example.com --token <token> --headers
```

One GET to `/`; lowercased response headers; `OBSERVED` with `missing`/`present` lists, or
`UNVERIFIED` on transport. No auth, no writes, no level/confirmation.

## Scope

- Recommended headers: `content-security-policy`, `x-content-type-options`,
  `x-frame-options`, `referrer-policy`, `permissions-policy`, `cross-origin-opener-policy`,
  and `strict-transport-security` for HTTPS only.
- Local: probe sidecar; live: same function in-process after the P1 gate.
- `--headers` opt-in; no change to default scans.
- Observation in `results.json`, CLI/JSON, report; no proof bundle; exit code unchanged.
- Tests: sidecar/parser/client/scan/CLI/report; Docker fixture with missing and present headers.

## Out of scope

- Treating missing headers as `EXPOSED`; grading/severity.
- Full header policy analysis, CSP validation, cookie flags, TLS grading.
- Hosted reports.

## Acceptance criteria

- Local/live `--headers` → one `headers` observation with missing/present.
- Transport failure → `UNVERIFIED`.
- No `--headers` → observations unchanged.
- Observation never `EXPOSED`/signed; exit unchanged.
- Report shows the observation, escaped; no "secure" claim.
- Default suite offline; Docker test opt-in.
