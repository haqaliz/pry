# Unauthenticated Endpoints, For Real (P3 remainder)

- **Type:** feat
- **Slug:** `unauthenticated-endpoints`
- **Owner:** aliz
- **Source:** inline brief. No GitHub issue.
- **Capability:** P3 remainder — missing authentication. Depends on P1, P2, the P3 probe
  sidecar, and `ETHICS.md`.

## Brief

Prove that an endpoint the owner says is protected returns data without an authentication
header. Endpoint discovery is the hard part, so the first slice requires the owner to
declare the paths. That makes the claim precise: "you said `/api/users` requires auth; here
is a 200 JSON response with no credentials."

The probe runs inside the existing sidecar against the sandboxed app. GET only, no cookies,
no auth header, no egress. A 2xx JSON/non-empty body is `EXPOSED`; 401/403/404, a redirect,
or a 2xx HTML/login page is `NOT_REPRODUCED`; 5xx or transport failure is `UNVERIFIED`.

## Current state

- P1, P2, and the first P3 slice (CORS, verbose errors, exposed secret files) are merged.
- `pry scan ./app` runs the three probes in `src/pry/probe/sidecar.py`.
- There is no endpoint flag and no unauthenticated request probe.
- `ETHICS.md` is approved.

## Scope

1. `pry scan ./app --endpoint /api/users --endpoint /api/admin` (repeatable).
2. Path-only validation: must start with `/`, must not contain `://`, whitespace, or a
   protocol-relative prefix. Reject absolute URLs; the probe only talks to the sandbox app.
3. Sidecar probe `unauth`: GET the path with no auth/cookie headers; no redirects; 5s
   timeout; 4 KiB body cap.
4. Verdict rules: 2xx + JSON content type or a JSON-looking body + non-empty → `EXPOSED`;
   401/403/404 → `NOT_REPRODUCED`; 2xx HTML (likely a login page) → `NOT_REPRODUCED`;
   5xx/transport → `UNVERIFIED`.
5. One result per endpoint, with request/response and evidence; append to `results.json`.
6. No `--endpoint` → the check is not run; the default three probes are unchanged.
7. Tests: sidecar, client, scan, CLI, and an opt-in Docker fixture with a 200 JSON endpoint
   and a 401 endpoint.

## Out of scope

- Endpoint discovery (OpenAPI, crawling, JS parsing).
- Authenticated/IDOR checks, exposed database rules, header-only findings.
- Live URL probing, levels 1–2.
- Claims that the app has "no authentication" beyond the declared endpoints.

## Acceptance criteria (draft)

- `--endpoint /api/users` against a 200 JSON fixture → `EXPOSED`, result has the request
  (no Authorization/Cookie) and response (status 200, JSON excerpt).
- `--endpoint /api/private` against a 401 fixture → `NOT_REPRODUCED`.
- 2xx HTML login page → `NOT_REPRODUCED`.
- 500 → `UNVERIFIED`.
- Absolute URL / `//evil` / whitespace path → exit 2, no request.
- No `--endpoint` → exactly the existing three results.
- App/sidecar no egress; cleanup; host repo unchanged.
- Default suite offline; Docker test opt-in.

## Notes

- The endpoint list is a declaration by the owner. The result is "this declared-protected
  path returned data without credentials," not "the whole app has no auth."
- This is the highest-value remaining floor check for the vibe-coded market (apps with no
  authentication at all); P4 expanded checks come after the floor suite.
