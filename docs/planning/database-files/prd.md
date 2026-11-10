# PRD — Exposed Database Files (P3 remainder)

- **Status:** Merged to `master` (2026-11-11). Served database file checks implemented;
  IDOR discovery, provider database/open-rule checks, live SSRF, Level 2, and hosted reports
  are deferred.
- **Owner:** aliz
- **Slug:** `database-files`
- **Capability:** P3 remainder — exposed database files

## Problem Statement

A database file committed to a public web root is a direct exposure: the app serves the
whole store to anyone with the path. This is common in vibe-coded apps (a checked-in
`data.db` or `dump.sql`). It is reproducible with one unauthenticated GET and a fixed
signature, so it fits the verdict contract: no guessing, no inference.

Provider rule checks (Firebase/Supabase) are a different problem. Proving ownership of a
third-party database host is not possible with the current P1 methods; a token for the app
origin does not prove the database project. Those checks stay deferred, and the docs say so.

## Goals & Success Metrics

1. Every local/live level 0 scan checks four fixed database paths with no credentials.
2. `EXPOSED` only for a same-origin 2xx with a SQLite header or SQL-dump signature; signed.
3. The stored body is a short signature excerpt; no dump is downloaded or kept.
4. No signature → `NOT_REPRODUCED`; transport → `UNVERIFIED`.
5. Provider open-rule checks remain explicitly deferred.

## Requirements

| ID | Requirement |
|---|---|
| M1 | Fixed paths `/data.db`, `/app.db`, `/db.sqlite`, `/dump.sql`; one GET each; no auth; no redirects. |
| M2 | SQLite detection from the `SQLite format 3\0` header; SQL dump detection from a leading `PRAGMA`/`CREATE TABLE`/`INSERT INTO`/`BEGIN TRANSACTION`/`DROP TABLE` after comments. |
| M3 | `EXPOSED` only for a 2xx same-origin response with a signature; signed by the shared path. |
| M4 | Store a signature excerpt only; no rows or binary content. |
| M5 | Reject 401/403/404 and HTML fallbacks as `NOT_REPRODUCED`; transport `UNVERIFIED`. |
| M6 | Run in the default local and live floor; no new flag or level. |
| M7 | Tests: sidecar probe, local/live, CLI/report, Docker fixture with a SQL dump. |
| M8 | Docs: DB file scope, excerpt policy, request counts, provider rules deferred, no secure. |

## Technical Considerations

- `probe_database(base_url, fetch=None)` in `sidecar.py`; add `database` to `PROBES`,
  `PROBE_ORDER`, and the live probe list.
- The URL is built from the target origin only; no user path, no cross-origin follow.
- `_read_text` already caps at 4 KiB and decodes; the SQLite magic survives decoding.
- On a match, replace the body with `"SQLite format 3\\x00 [binary database content
  withheld]"` or `<signature> [SQL dump content withheld]`.
- No new dependencies; no config; no credentials.

## Risks

| Risk | Severity | Mitigation |
|---|---|---|
| **False `EXPOSED`** from an HTML page mentioning SQL. | Med/High | Anchor the SQL signature at the start after comments; require a 2xx same-origin response; safe fixture test. |
| **Sensitive rows in the stored proof.** | High/High | Store only the signature excerpt; never the full dump. |
| **Extra requests on a live target.** | Low/Low | Four GETs; bounded; no redirects. |
| **Provider rules read as covered.** | Med/High | Docs and report say provider/open-rule checks are deferred. |
| **A 200 SPA fallback at a DB path.** | Low/Med | HTML/non-signature bodies are `NOT_REPRODUCED`. |

**Hard question:** an exposed database file is a real data exposure, but the check only
covers four conventional paths. It does not prove the app has no other database exposure.

## Out of Scope

- Firebase/Supabase rule checks and third-party DB ownership.
- Database discovery, credential use, bulk download, SQL injection.
- Header policy analysis, live SSRF, live rate-limit, Level 2, hosted reports.

## Acceptance Tests

| ID | Test | Expected |
|---|---|---|
| AT1 | SQLite header at `/data.db` | EXPOSED, signed, report |
| AT2 | SQL dump at `/dump.sql` | EXPOSED; excerpt only |
| AT3 | 401/403/404 | NOT_REPRODUCED |
| AT4 | HTML 200 fallback | NOT_REPRODUCED |
| AT5 | Transport failure | UNVERIFIED |
| AT6 | Same-origin redirect/foreign response | not a match |
| AT7 | Docker fixture | served dump → EXPOSED; cleanup |
| AT8 | Default suite | offline; Docker opt-in |
| AT9 | Docs | DB file scope, excerpt, provider rules deferred, no secure |

## Self-Critique

- 🟡 **Conventional paths only.** State that in the result and docs; no global claim.
- 🟡 **Excerpt, not the dump.** It proves the response without exfiltrating rows.
- 🟢 **One request per path, fixed, same-origin, no credentials.**
