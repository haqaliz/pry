# Live Read-Only Scans (P3/P5/P6 live slice)

- **Type:** feat
- **Slug:** `live-readonly-scan`
- **Owner:** aliz
- **Source:** inline brief. No GitHub issue.
- **Capability:** P3/P5/P6 live read-only slice. Depends on P1, the P3 probes, P5 signed
  bundles, P6 report/corpus, and `ETHICS.md`.

## Brief

`pry scan https://example.com --token <token>` still reports `UNVERIFIED`. The P1 gate, the
probes, the signed bundles, and the report all exist, but they only work for local repos.
This slice runs the same four read-only probes against a live URL the user has proven they
own, from the host, with no Docker sandbox.

P1 is the gate: the token must validate for the target origin before any request is sent. The
scan is read-only: GETs only, no auth, no cookies, no writes, 4–6 requests. The result is
signed and reportable like a local scan.

## Current state

- P1 ownership tokens work; `pry scan URL` validates the token then prints `UNVERIFIED`.
- The P3 probes live in `src/pry/probe/sidecar.py` as stdlib-only functions.
- P5 signs every EXPOSED local finding; P6 writes the report/corpus.
- Live scans are not implemented.

## Scope

1. `scan_live(url, token, endpoints=None, out=None)`:
   - Normalize the target, validate the P1 token for the origin; no network request before
     validation.
   - Build a live snapshot: kind `live`, URL/origin, ownership proof type, timestamp; no
     git/image/sandbox.
   - Run the existing `cors`, `errors`, `secrets`, and declared `unauth` probes in-process
     against the origin.
   - Sign EXPOSED results, write `snapshot.json`/`results.json`/proofs/corpus/report.
2. CLI: `pry scan URL --token TOKEN [--endpoint PATH] [--report] [--json] [--out DIR]`;
   exit 1 if any EXPOSED, 0 otherwise, 2 for ownership/usage errors.
3. Report: show the live URL/host and ownership proof type; `VALID`/`INVALID` proofs.
4. Read-only safety: GET/HEAD only; no Authorization/Cookie; no writes; no redirects across
   origins; 5s timeout; 4 KiB body cap; at most 4 default probes plus declared endpoints.
5. Tests: fake probes offline; a loopback HTTP server integration with a real token; no
   third-party targets; no Docker.
6. Docs: live read-only scope, P1 requirement, no writes, no "secure."

## Out of scope

- Live write-based checks, levels 1–2, P4.
- IDOR/DB rules, endpoint discovery.
- Auth/cookie scanning; authenticated requests.
- Hosted reports, public sharing.
- Any claim the live app is secure.

## Acceptance criteria

- Valid token + live fixture → CORS/errors/secrets (and declared unauth) EXPOSED, signed,
  report written.
- Missing/invalid token → exit 2, no request sent to the target.
- The P1 token never appears in results, proofs, reports, or logs.
- Live snapshot kind `live`, URL, ownership proof type.
- Report shows the host, ownership proof, and proof statuses.
- Only GET/HEAD; no auth/cookie headers; no writes.
- Default suite offline; loopback integration uses a local server only.
- No "secure" claim anywhere.

## Notes

- The sandbox no-egress rule applies to local intake; a live scan is the user's authorized
  target and necessarily uses the network. The P1 token is the authorization.
- The probes are shared with the local sidecar; no duplicate probe logic.
- A live scan is 4–6 GETs. Rate-limit probing and SSRF are P4 and require higher intensity.
