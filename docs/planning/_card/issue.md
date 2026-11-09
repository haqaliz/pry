# Local SSRF, Level 1 (P4 first slice)

- **Type:** feat
- **Slug:** `ssrf-local`
- **Owner:** aliz
- **Source:** inline brief. No GitHub issue.
- **Capability:** P4 Level 1, local SSRF. Depends on P1–P3, P5 bundles, P6 report,
  and `ETHICS.md`.

## Brief

Level 1 is expanded, still read-only, but requires explicit confirmation. The first P4 slice
is SSRF against a local sandbox app: the owner declares a fetch endpoint and parameter, Pry
sends it a callback URL on the sandbox's internal network, and the callback records the hit.
`EXPOSED` means the app actually fetched the callback. No live SSRF, no rate-limit, no writes.

## Flow

```bash
pry scan ./my-app --level 1 --confirm \
  --ssrf-endpoint /api/fetch --ssrf-parameter url
```

1. Boot the app in the P2 sandbox and run the floor probes.
2. Start a callback sidecar on the same `--internal` network, alias `pry-callback`.
3. Send `GET /api/fetch?url=http://pry-callback:9000/<nonce>` to the app.
4. The app fetches the callback; the callback logs the request.
5. `EXPOSED` iff the log contains the nonce; `NOT_REPRODUCED` if the app responds but no
   hit; `UNVERIFIED` if the app request or callback control fails.

## Scope

- `--level 1 --confirm --ssrf-endpoint PATH --ssrf-parameter NAME` for a local repo.
- Level 1 requires `--confirm`; missing → exit 2. Level 2 remains unsupported.
- SSRF flags without level 1 or on a live URL → exit 2.
- Callback sidecar: Python image, scripts mounted read-only, alias `pry-callback`, port 9000,
  hit log in `/tmp`, no egress, no host port, all existing sandbox security flags.
- Probe script: GET query parameter only; path-only endpoint; token parameter; 10s app
  timeout; 5s callback wait; 4KiB body cap.
- Result: request = app request; response = callback hit; evidence = app status + hit path;
  signed/report/corpus.
- Tests: scripts with local servers; scan fakes; opt-in Docker fixture with `/api/fetch`.

## Out of scope

- Live SSRF (needs a public callback), rate-limit probing.
- Level 2/write-based confirmation, auth, discovery, DB rules.
- POST/body/header injection; only GET query parameters.
- Hosted reports.

## Acceptance criteria

- `--level 1 --confirm` + a vulnerable fixture → `EXPOSED`, callback hit, signed proof,
  report, no leftovers.
- App responds but no callback hit → `NOT_REPRODUCED`.
- Invalid endpoint/parameter, missing `--confirm`, level 2, live URL + SSRF flags → exit 2,
  no request.
- Callback and app have no egress; no host port; no Docker socket.
- The callback sidecar and workspace are removed on success/failure/SIGINT.
- Default suite offline; Docker SSRF test opt-in.
- No "secure" claim.
