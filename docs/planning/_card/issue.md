# Live SSRF with a User Callback (P4 remainder)

- **Type:** feat
- **Slug:** `live-ssrf`
- **Owner:** aliz
- **Source:** inline brief. No GitHub issue.
- **Capability:** P4 — live Level 1 SSRF, proven by a user-supplied callback.

## Brief

Local SSRF is callback-proven inside the sandbox. A live check needs a callback the target can
reach. Instead of hosting one, the owner supplies a callback base URL that implements a tiny
poll contract: `GET <base>/<nonce>` returns 200 after the nonce was hit, 404 before. Pry sends
one declared SSRF request with that nonce URL, then polls up to three times. A 200 is
`EXPOSED`; no hit is `NOT_REPRODUCED`.

## Flow

```bash
pry scan https://app.example.com --token <token> \
  --level 1 --confirm \
  --ssrf-endpoint /api/fetch --ssrf-parameter url \
  --ssrf-callback-url https://callback.example/pry
```

The target app receives `/api/fetch?url=https%3A%2F%2Fcallback.example%2Fpry%2F<nonce>`. If it
fetches that URL, the callback records the nonce. Pry polls
`https://callback.example/pry/<nonce>` up to three times, 0.5s apart. The callback must return
200 only after the hit.

## Scope

- Live `--level 1 --confirm --ssrf-endpoint PATH --ssrf-parameter NAME
  --ssrf-callback-url URL`; P1 token required.
- Callback URL: absolute HTTPS (HTTP only for loopback tests), no userinfo/query/fragment;
  different origin from the target; path prefix allowed.
- One SSRF GET + up to three callback polls; no auth/cookies; no redirects.
- `EXPOSED` only when a callback poll returns 200; signed proof with the SSRF pair and the
  callback pair.
- SSRF 401/403/404 or no hit → `NOT_REPRODUCED`; SSRF 5xx/transport or callback
  transport/5xx → `UNVERIFIED`.
- Local SSRF unchanged; `--ssrf-callback-url` on a local path exits 2.
- Tests: unit probe, live scan, CLI, loopback end-to-end; docs/ETHICS.

## Out of scope

- Pry-hosted callback infrastructure, tunnels, internal port scanning, credential use.
- IDOR discovery, hosted reports.

## Acceptance criteria

- SSRF 200 + callback 200 → EXPOSED, signed, report.
- SSRF 200 + callback 404 on all polls → NOT_REPRODUCED.
- SSRF 401/403/404 → NOT_REPRODUCED, no polls.
- SSRF 5xx/transport or callback transport → UNVERIFIED.
- Missing callback, missing confirmation/token, or same-origin callback → exit 2, no request.
- Local path + `--ssrf-callback-url` → exit 2.
- No auth/cookies; no redirects; nonce is per-run.
- Docs state callback ownership and the poll contract; no secure.
