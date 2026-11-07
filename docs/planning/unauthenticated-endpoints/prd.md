# PRD — Unauthenticated Endpoints (P3 remainder)

- **Status:** Merged to `master` (2026-11-07). Missing-auth declarations implemented;
  discovery, IDOR, exposed database rules, live URL, and levels 1–2 remain deferred.
- **Owner:** aliz
- **Slug:** `unauthenticated-endpoints`
- **Capability:** P3 remainder (missing authentication)

## Problem Statement

The market evidence is blunt: roughly 2,000 of the corporate apps found on Lovable,
Replit, and Base44 had no authentication at all. The floor suite's highest-value remaining
check is therefore: does an endpoint the owner says is protected return data without
credentials?

Endpoint discovery is the hard part. A crawler or a source heuristic would guess, and a
guess is not the product. This slice makes the claim precise: the owner declares the
protected paths, and Pry sends the unauthenticated request and captures the response.

**If we do not build this:** the floor suite misses the most common exposure in the target
market, and users have to eyeball auth themselves.

**What we are choosing not to build:** endpoint discovery, IDOR with two identities,
Firebase/Supabase rule checks, header-only findings, live URL probing, levels 1–2.

## Goals & Success Metrics

1. `pry scan ./app --endpoint /api/users` sends a GET with no auth and cookies, inside the
   sandbox.
2. `EXPOSED` only when a declared-protected path returns a 2xx JSON/non-empty body; the
   result carries the request/response pair.
3. No `EXPOSED` for 401/403/404, a redirect, a 2xx HTML login page, a 5xx, or a transport
   failure.
4. No endpoint flag → the existing three probes are unchanged.
5. The sandbox and sidecar still have no egress; cleanup still holds.

Success metrics:

- Vulnerable fixture `/api/users` → `EXPOSED`; safe fixture `/api/users` 401 →
  `NOT_REPRODUCED`.
- 2xx HTML login page → `NOT_REPRODUCED`; 500 → `UNVERIFIED`.
- Absolute URL / protocol-relative / whitespace path → exit 2, no request.
- Default suite offline; Docker test opt-in.

## User Personas & Scenarios

**App owner.** Knows `/api/users` and `/api/admin` should require a session. Runs
`pry scan ./app --endpoint /api/users --endpoint /api/admin`. Pry reports which paths
returned data with no auth, and which refused.

**Maintainer.** Adds a probe without changing the endpoint contract: the sidecar receives a
path that is already validated as path-only.

## Requirements

### Must-have

| ID | Requirement |
|---|---|
| M1 | Repeatable `--endpoint PATH` on `pry scan` for local paths. |
| M2 | Path-only validation: starts with `/`, no `://`, no leading `//`, no whitespace or control characters, max 2048 chars. Invalid → exit 2, no request. |
| M3 | Sidecar probe `unauth`: GET `base_url + path` with only `User-Agent: pry/0.1`; no Authorization, Cookie, or other credentials; no redirects; 5s timeout; 4 KiB body cap. |
| M4 | Verdict: 2xx + JSON content type or JSON-looking body + non-empty → `EXPOSED`; 401/403/404 → `NOT_REPRODUCED`; 2xx HTML → `NOT_REPRODUCED` (likely a login page); 5xx/transport → `UNVERIFIED`. |
| M5 | One result per endpoint with request, response, evidence, verdict. Append to `results.json`; summary counts. |
| M6 | No `--endpoint` → the check is not added; the three existing results are unchanged. |
| M7 | `--json` and human output include the unauth results; exit 1 if any `EXPOSED`. |
| M8 | Offline unit tests for sidecar/client/scan/CLI; opt-in Docker fixtures for a 200 JSON endpoint and a 401 endpoint. |
| M9 | Docs state the declaration model, the JSON-only EXPOSED rule, and what is deferred. |
| M10 | No egress, no auth headers, no cookies, no writes; cleanup unchanged. |

### Should-have

- `--endpoints-file` with one path per line.
- A `--only unauth` filter.
- Method selector (`GET` default; `HEAD` optional).

## Technical Considerations

- The sidecar already runs on the internal network against `http://app:<port>`. The new
  probe is a fourth function in `sidecar.py`, dispatched by `main` with a third argument
  (the path).
- `ProbeClient.run("unauth", endpoint=path)` appends the path as a fourth argv element.
- `scan_local(..., endpoints=None)` runs the three default probes, then one `unauth` probe
  per endpoint through the same sidecar. It appends the results before writing
  `results.json`.
- The path is validated on the host and again in the sidecar; the sidecar refuses anything
  that is not path-only.
- The body is captured for the proof but capped at 4 KiB. The fixture uses fake data. A
  real endpoint may return PII; the owner owns the target, and the result is local-only.
  Redaction beyond secret-shaped values is P5.
- `EXPOSED` wording: "declared-protected path returned status 200 with a JSON body and no
  credentials." It does not claim the whole app lacks auth.

## Risks & Open Questions

| Risk | Severity | Mitigation |
|---|---|---|
| **False `EXPOSED`** because the owner declared a genuinely public endpoint. | Med/Med | The result quotes the owner's declaration; docs say it is a declaration, not a global auth conclusion. |
| **False `EXPOSED`** on a 200 JSON error/health payload from a protected path. | Med/Med | Require non-empty JSON; the result shows the excerpt; the owner can judge. |
| **False `NOT_REPRODUCED`** on a 200 HTML login page. | Med/Med | Treat 2xx HTML as NOT_REPRODUCED and say why. |
| **PII in the captured body.** | Med/High | 4 KiB cap, local-only, 0600; P5 owns fuller redaction. |
| **Path injection/SSRF** via an absolute URL or `//host`. | High/High | Path-only validation on host and sidecar; reject schemes, leading `//`, whitespace. |
| **Auth via cookies not tested** because Pry sends none. | Med/Med | That is the point: an unauthenticated request. State it. |

**Hard question:** if the owner has to supply the endpoints, are we still finding missing
auth, or just confirming the owner's suspicion? For this slice, confirmation is the
product: a reproduced 200 with data and no credentials is the proof. Discovery comes later.

## Out of Scope

- Endpoint discovery/crawling/OpenAPI/JS parsing.
- IDOR with two identities, authenticated checks, Firebase/Supabase rules.
- Header-only findings, live URL probing, levels 1–2.
- Claims that the app has "no authentication" beyond the declared paths.

## Acceptance Tests

| ID | Test | Expected |
|---|---|---|
| AT1 | `/api/users` 200 JSON, no auth | `EXPOSED`; request has no Authorization/Cookie |
| AT2 | `/api/private` 401 | `NOT_REPRODUCED` |
| AT3 | 2xx HTML login page | `NOT_REPRODUCED` |
| AT4 | 500 | `UNVERIFIED` |
| AT5 | Absolute URL / `//evil` / whitespace | exit 2, no request |
| AT6 | No `--endpoint` | exactly 3 results |
| AT7 | Multiple endpoints | one result each, summary counts |
| AT8 | `--json` and human output | include the new results |
| AT9 | Sandbox egress/cleanup | unchanged: no egress, no leftovers |
| AT10 | Default suite | offline; Docker test opt-in |

## Self-Critique

- 🟡 **Declaration, not discovery.** The owner supplies the paths; the result is precise
  but not exhaustive. Say so.
- 🟡 **JSON-only EXPOSED** avoids login-page false positives but may miss a protected path
  that returns sensitive HTML. Defer; manual review.
- 🟢 **The request/response pair is the proof**, and the path validation closes the obvious
  SSRF hole.
