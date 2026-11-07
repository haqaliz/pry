# PRD — Live Read-Only Scans

- **Status:** Merged to `master` (2026-11-08). Live read-only scans implemented; live
  write-based checks, levels 1–2, P4, IDOR/DB, and hosted reports are deferred.
- **Owner:** aliz
- **Slug:** `live-readonly-scan`
- **Capability:** P3/P5/P6 live read-only slice

## Problem Statement

The market is live apps, but `pry scan https://example.com --token <token>` still reports
`UNVERIFIED`. P1 proves ownership, the probes reproduce issues, P5 signs findings, and P6
reports them — all only for local repos. The gap is the live path.

This slice runs the same four read-only probes against a live URL the user has proven they
own, from the host, with no Docker sandbox. The P1 token is the authorization and is validated
before any request is sent. The scan is GET-only, sends no credentials, makes 4–6 requests, and
produces the same signed bundle/report as a local scan.

## Goals & Success Metrics

1. A valid P1 token + live fixture → CORS/errors/secrets (and declared unauth) EXPOSED,
   signed, report written.
2. Missing/invalid token → exit 2, no target request.
3. Only GET/HEAD; no Authorization/Cookie; no writes; no cross-origin redirects.
4. Live snapshot records kind `live`, URL, ownership proof type; no token.
5. Report shows the host, ownership proof, and proof statuses.
6. Default suite offline; a loopback HTTP server integration uses a real token.

## Requirements

| ID | Requirement |
|---|---|
| M1 | `scan_live(url, token, endpoints=None, out=None) -> ScanOutcome`: normalize target, validate token for the origin, then run probes. No target request before validation. |
| M2 | Live snapshot: `version`, `sandbox_id` `live-*`, `created_at`, target{path=origin, kind="live", url, ownership_proof, git/image fields null}, project nulls/port, sandbox `network="live"`, result ready. |
| M3 | Run the existing `probe_cors`, `probe_errors`, `probe_secrets`, and `probe_unauth` functions in-process; convert to `ProbeResult`. |
| M4 | Sign every EXPOSED result (P5), write proofs/results/corpus (P6), return `ScanOutcome`. |
| M5 | CLI URL path: `pry scan URL --token TOKEN [--endpoint PATH] [--report] [--json] [--out DIR]`; exit 1 for any EXPOSED, 0 clean, 2 ownership/usage. |
| M6 | Report: live host/basename, URL, ownership proof type, findings, proof statuses; no token. |
| M7 | Safety: GET only; no auth/cookie headers; no writes; no cross-origin redirects; 5s timeout; 4KiB cap; at most the four defaults plus declared endpoints. |
| M8 | Tests: unit with fake probes; loopback HTTP server integration with a real P1 token; no third-party targets; no Docker. |
| M9 | Docs: P1 requirement, read-only, request count, no "secure," live writes/levels 1–2 deferred. |
| M10 | The P1 token never appears in results, proofs, reports, logs, or errors. |

## Technical Considerations

- Reuse `sidecar.py` probe functions; they are stdlib-only and already tested. The live path
  calls them with `urllib_fetch` against `target.origin`.
- The P1 token is validated with `TokenSigner.validate(token, target)`; use the returned
  `proof_type` in the snapshot. Do not store the token.
- Extract the shared local finalization (sign EXPOSED, summarize, results.json, corpus) so the
  local and live paths cannot diverge. If refactoring is risky, duplicate only the small
  sign/write block and keep it covered by tests.
- The live snapshot has no git/image/workspace/container. The report must accept `kind=live`,
  `path=URL`, and null commit/dirty.
- `_target_basename` must handle URLs (`urlsplit(...).hostname`); the report should not show
  the full local run path.
- The live scan uses the host network; the sandbox no-egress rule applies only to local
  intake. The P1 token authorizes the target.
- The scan is not rate-limit probing; 4–6 requests total. No concurrency.
- Redirects are not followed across origins (the sidecar fetch already disables redirects).

## Risks & Open Questions

| Risk | Severity | Mitigation |
|---|---|---|
| **P1 bypass**: a request before token validation. | High/Critical | Validate target/token before constructing probes/fetch; test with a sentinel fetch that must not run. |
| **Live side effect** from a GET (webhook/cache). | Med/High | One GET per probe, no auth, no query that mutates; document; the user owns the target. |
| **Token leakage** into results/report/logs. | High/High | Never include the token; test the output. |
| **Cross-origin redirect** to a third party. | Med/High | Fetch disables redirects; a 3xx is not followed. |
| **False positives** from a CDN/HTML fallback. | Med/Med | Same probe rules as local: CORS exact pair, strong error signatures, secret key/value, unauth JSON. |
| **Report PII** from a live response. | Med/High | Use the redacted probe output; local 0600; no upload. |
| **"Live scan" read as permission to write.** | High/High | GET only; docs say levels 1–2 are not implemented. |

**Hard question:** should a live read-only scan require a second explicit confirmation beyond
the P1 token? The token already proves ownership; this slice treats it as sufficient for
read-only GETs. Higher intensity will add the per-target confirmation.

## Out of Scope

- Write-based checks, levels 1–2, P4.
- IDOR/DB rules, endpoint discovery, authenticated scans.
- Hosted/public reports, live write confirmation.
- Any claim the live app is secure.

## Acceptance Tests

| ID | Test | Expected |
|---|---|---|
| AT1 | Valid token + fake probes | EXPOSED results, proofs, report |
| AT2 | Missing/invalid token | exit 2, no target request |
| AT3 | Live snapshot | kind live, URL, ownership proof, no token |
| AT4 | Loopback server | CORS/errors/secrets/unauth EXPOSED |
| AT5 | Report | host, ownership proof, VALID proofs |
| AT6 | No auth/cookie headers | request evidence only User-Agent |
| AT7 | Cross-origin redirect | not followed |
| AT8 | P1 token leak scan | token absent from outputs |
| AT9 | Default suite | offline; loopback only; no Docker |
| AT10 | Docs | live read-only scope, no secure |

## Self-Critique

- 🟡 **Live GETs are not zero-risk.** A GET can trigger a webhook; the user owns the target,
  and the request count is minimal. Say so.
- 🟡 **P1 token is the only gate.** That is the design; a second confirmation is a P4 concern.
- 🟢 **The probe logic is shared**, so the live path cannot silently drift from the local one.
