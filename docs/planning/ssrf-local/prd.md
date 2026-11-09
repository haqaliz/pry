# PRD — Local SSRF, Level 1 (P4 first slice)

- **Status:** Merged to `master` (2026-11-10). Local Level 1 SSRF implemented; rate-limit,
  live SSRF, Level 2, and write-based checks are deferred.
- **Owner:** aliz
- **Slug:** `ssrf-local`
- **Capability:** P4 Level 1, local SSRF

## Problem Statement

SSRF is a common failure in apps that fetch user-supplied URLs. It is reproducible when the
app actually fetches a URL the tester controls. The local sandbox is the safest place to
prove it: the callback can live on the sandbox's internal network, with no public callback
service and no egress.

This is a **Level 1** check: still read-only, but expanded and explicitly confirmed per target.
The owner declares the fetch endpoint and query parameter. Pry sends the endpoint a callback
URL; `EXPOSED` means the callback received the matching request.

**If we do not build this:** P4 has no reproducible check, and the suite cannot prove one of
the most common server-side request-forgery failures.

**What we are choosing not to build:** live SSRF (needs a public callback), rate-limit
probing, write-based confirmation, POST/body/header SSRF, discovery.

## Goals & Success Metrics

1. `--level 1 --confirm --ssrf-endpoint /api/fetch --ssrf-parameter url` on a local fixture
   → callback hit, `EXPOSED`, signed proof, report, no leftovers.
2. An app that responds but does not fetch the callback → `NOT_REPRODUCED`.
3. Missing `--confirm`, missing SSRF flags, level 2, or a live URL + SSRF flags → exit 2, no
   target request.
4. Callback and app have no egress; no host port; no Docker socket.
5. Default suite offline; Docker SSRF test opt-in.

## Requirements

| ID | Requirement |
|---|---|
| M1 | CLI: `pry scan PATH --level 1 --confirm --ssrf-endpoint PATH --ssrf-parameter NAME`. Level 1 requires `--confirm`; missing → exit 2 `CONFIRMATION_REQUIRED`. Level 2 remains unsupported. |
| M2 | SSRF flags require level 1 and a local path. On a URL, or level 0, → exit 2 `SSRF_REQUIRES_LOCAL_LEVEL1`. |
| M3 | Validate endpoint path-only and parameter token-like; invalid → exit 2 `SSRF_CONFIG_INVALID`, no request. |
| M4 | Start a callback sidecar on the sandbox `--internal` network with alias `pry-callback`, port 9000, scripts mounted read-only, hit log in `/tmp`, no egress, no host port, all existing sandbox security flags. |
| M5 | Probe: GET `app_base + endpoint + "?" + urlencode({parameter: "http://pry-callback:9000/<nonce>"})`; 10s app timeout; poll the hit log up to 5s for the nonce; 4KiB body cap. |
| M6 | `EXPOSED` iff the hit log contains the nonce; `NOT_REPRODUCED` if the app responds but no hit; `UNVERIFIED` if the app request, callback control, or hit read fails. |
| M7 | Result: `probe="ssrf"`, request = the app request (with the callback URL), response = the callback hit, evidence = app status + hit path. Signed and reportable. |
| M8 | Cleanup: remove the callback sidecar, probe sidecar, app, network, and workspace on success, failure, timeout, and SIGINT. |
| M9 | Tests: callback server and probe script with local servers; scan fakes; opt-in Docker fixture with `/api/fetch`. No third-party targets. |
| M10 | Docs/ETHICS: Level 1 confirmation, local sandbox only, GET query only, no egress for callback/app, live SSRF deferred, no secure. |

## Technical Considerations

**Callback sidecar.** Reuse `python:3.9-slim`, mount `src/pry/probe/` read-only at `/pry`,
run `python /pry/callback_server.py` with `--network-alias=pry-callback`. The server listens on
0.0.0.0:9000, appends each request to `/tmp/pry-callback-hits.jsonl`, and returns 200. The
sandbox flags (`--cap-drop=ALL`, `--security-opt=no-new-privileges`, `--read-only`,
`--tmpfs=/tmp:rw,exec`, `--user`, limits) apply. No `-p`, no socket.

**Probe script.** `python /pry/ssrf_probe.py APP_BASE ENDPOINT PARAMETER NONCE CALLBACK_BASE`.
It builds the callback URL, sends the app GET with `urllib`, caps the body, polls the hit log
for `/<nonce>`, and prints one JSON object:
`{hit, cause, request, app_response, callback_hit}`. It never stores credentials; there are
none.

**Scan integration.** `scan_local(..., level=1, ssrf_config=...)`:
1. Floor probes and their sidecar run as today.
2. Start the callback sidecar on the same network; run the SSRF probe via `docker exec` into
   the callback sidecar (the script is mounted there).
3. Append the SSRF result; remove the callback sidecar in `finally`.
4. Finalize (sign EXPOSED, results/corpus/report) as today.
The callback sidecar name is `pry-callback-<sandbox_id>`; the app alias is `app`.

**Proof semantics.** The callback hit is the reproduced exploit: the app made the request to
the callback. The result's `request` is the app request (with the callback URL); the
`response` is the callback's recorded request. The app response status is evidence, not the
primary proof. The nonce ties the two together.

**Confirmation.** Level 1 is not the default. `--confirm` is the explicit per-target
confirmation required by the roadmap. The target is a local sandbox; no live target is
touched. A live URL with SSRF flags is refused until a public callback design exists.

**Safety.** GET query only; no POST/body/header injection; no response data from the app is
needed; the callback only records its own request. The app and callback have no egress. The
callback is internal and removed after the run.

## Risks & Open Questions

| Risk | Severity | Mitigation |
|---|---|---|
| **App blocks internal/private URLs** → no hit. | Med/High | `NOT_REPRODUCED`, not EXPOSED; the owner may need to whitelist the callback for the test. Document. |
| **App is slow to fetch** → race. | Med/Med | Poll 5s; 10s app timeout; `UNVERIFIED` on control failure. |
| **Callback sidecar complexity** / cleanup. | Med/High | Reuse sandbox flags; `finally` removal; integration tests; no leftovers. |
| **False EXPOSED** from an unrelated callback request. | High/High | Per-run nonce; check the exact path; callback is fresh per run. |
| **Level 1 confirmation bypass.** | High/High | CLI requires `--confirm` and level 1; tests; no live. |
| **SSRF flags on a live URL** could imply a public callback. | High/High | Refuse with `SSRF_REQUIRES_LOCAL_LEVEL1`. |
| **Proof overclaim**: callback hit proves the app fetched a URL, not arbitrary egress. | Med/High | Evidence says "the app fetched the callback URL"; no broader claim. |

**Hard question:** the callback is on the sandbox's internal network, so a hit proves the app
will fetch an internal URL. Does that prove SSRF against an external attacker-controlled host?
It proves the fetch primitive; external reachability depends on the app's network policy. The
result should say exactly that.

## Out of Scope

- Live SSRF/public callback, rate-limit probing, Level 2/write confirmation.
- POST/body/header injection, auth, discovery, DB rules.
- Hosted reports.

## Acceptance Tests

| ID | Test | Expected |
|---|---|---|
| AT1 | `--level 1 --confirm` + vulnerable fixture | EXPOSED, callback hit |
| AT2 | App responds, no hit | NOT_REPRODUCED |
| AT3 | Missing `--confirm` | exit 2, no scan |
| AT4 | Missing/invalid endpoint/parameter | exit 2, no request |
| AT5 | Level 2 | exit 2 |
| AT6 | Live URL + SSRF flags | exit 2 |
| AT7 | Callback/app egress | blocked |
| AT8 | Cleanup after success/failure/SIGINT | no sidecars/network/workspace |
| AT9 | Signed proof/report | EXPOSED signed; report shows hit |
| AT10 | Default suite | offline; Docker SSRF opt-in |

## Self-Critique

- 🟡 **Internal callback ≠ external SSRF.** The primitive is proven; external egress is not.
  The wording must be exact.
- 🟡 **The app may block private ranges**, producing a false negative. The safe fixture tests
  this; docs explain.
- 🟢 **The callback hit is a reproduced request**, not a heuristic.
