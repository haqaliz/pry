# PRD — Live SSRF with a User Callback (P4 remainder)

- **Status:** Approved on standing instruction (2026-11-11)
- **Owner:** aliz
- **Slug:** `live-ssrf`
- **Capability:** P4 — live Level 1 SSRF with a user-supplied callback

## Problem Statement

SSRF is proven by an out-of-band hit, not by the app echoing a URL. Local SSRF uses a callback
sidecar on the sandbox network. A live target needs a callback the target can reach, but Pry
does not host public infrastructure. The owner can supply a callback base URL with a simple
poll contract: a per-nonce GET returns 200 only after the hit. Pry sends one SSRF request and
polls the callback. A 200 is a reproduced fetch.

## Goals & Success Metrics

1. Live `--level 1 --confirm` with endpoint, parameter, and callback URL runs one SSRF GET and
   up to three callback polls.
2. `EXPOSED` only when a callback poll returns 200; signed proof with both pairs.
3. No callback hit is `NOT_REPRODUCED`; transport/5xx is `UNVERIFIED`.
4. Missing token/confirmation/callback or a same-origin callback exits 2 before any request.
5. Local SSRF is unchanged; a local path with a callback URL exits 2.

## Requirements

| ID | Requirement |
|---|---|
| M1 | Live SSRF requires level 1 + `--confirm`, a P1 token, `--ssrf-endpoint`, `--ssrf-parameter`, `--ssrf-callback-url`. |
| M2 | Callback URL: absolute HTTPS (HTTP loopback only), no userinfo/query/fragment, path allowed; origin differs from the target. |
| M3 | One SSRF GET with the nonce callback URL; then up to 3 callback GETs, 0.5s apart; no auth/cookies/redirects. |
| M4 | `EXPOSED` only on callback poll 200; evidence names the nonce and the callback; signed proof. |
| M5 | SSRF 401/403/404 or no hit → `NOT_REPRODUCED`; SSRF 5xx/transport or callback transport/5xx → `UNVERIFIED`. |
| M6 | Local path with `--ssrf-callback-url` exits 2; local SSRF keeps the built-in callback. |
| M7 | Tests: unit probe, live scan, CLI, loopback end-to-end; no third-party target. |
| M8 | Docs/ETHICS: callback ownership, poll contract, no internal scanning, no secure. |

## Technical Considerations

- `src/pry/probe/live_ssrf.py`: `LiveSsrfConfig`, `validate_live_ssrf`, `probe_live_ssrf`.
- Reuse `validate_ssrf` for endpoint/parameter; add callback validation.
- Reuse `urllib_fetch`/`TransportError`/`Response`; `new_nonce`; `redact_headers`.
- Result `probe="ssrf"`, request = SSRF GET, response = SSRF response with
  `response["callback"] = {"request": ..., "response": ..., "attempts": N}`.
- `scan_live(..., ssrf_config=None)` runs it after the read-only probes; finalize signs.
- CLI `--ssrf-callback-url`; live gate; local rejection.
- No new dependencies; Python 3.9.

## Risks

| Risk | Severity | Mitigation |
|---|---|---|
| **Using a third-party callback without permission.** | High/High | Docs require a callback you own; the URL is explicit. |
| **False `EXPOSED` from a pre-existing nonce.** | High/High | 128-bit per-run nonce; the callback must be 404 before the hit. |
| **Internal port scanning / broad SSRF.** | Med/High | One declared endpoint/parameter and one callback URL; no port sweep. |
| **Callback service is down.** | Med/Med | `UNVERIFIED`, not `EXPOSED`; no retries beyond 3. |
| **The app responds 200 without fetching.** | High/High | The callback hit is the only EXPOSED condition. |
| **Same-origin callback ambiguity.** | Med/Med | Reject a callback on the target origin. |

**Hard question:** the callback is the user's own service; a malicious user could fake a 200.
Pry targets owners checking their own app, and the proof says the callback recorded the nonce;
it is not a third-party attestation.

## Out of Scope

- Pry-hosted callback infrastructure, tunnels, internal port scanning, credential use.
- IDOR discovery, hosted reports.

## Acceptance Tests

| ID | Test | Expected |
|---|---|---|
| AT1 | SSRF 200 + callback 200 | EXPOSED, signed |
| AT2 | SSRF 200 + callback 404 all polls | NOT_REPRODUCED |
| AT3 | SSRF 401/403/404 | NOT_REPRODUCED, no polls |
| AT4 | SSRF 5xx/transport | UNVERIFIED |
| AT5 | Callback transport | UNVERIFIED |
| AT6 | Missing callback/confirm/token | exit 2, no request |
| AT7 | Same-origin/HTTP non-loopback callback | exit 2 |
| AT8 | Local path + callback URL | exit 2 |
| AT9 | Loopback end-to-end | EXPOSED, proof verifies |
| AT10 | Docs | contract, ownership, no secure |

## Self-Critique

- 🟡 **The callback contract is user infrastructure.** That is the price of no Pry-hosted
  service; the docs are explicit.
- 🟡 **One declared fetch is not a full SSRF audit.** Say so.
- 🟢 **The callback hit is a real out-of-band reproduction, not an echo.**
