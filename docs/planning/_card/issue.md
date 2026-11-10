# Exposed Database Files (P3 remainder)

- **Type:** feat
- **Slug:** `database-files`
- **Owner:** aliz
- **Source:** inline brief. No GitHub issue.
- **Capability:** P3 remainder — exposed database files served by the app.

## Brief

The floor list includes exposed database/open rules. Provider rule checks (Firebase,
Supabase) need an ownership proof for a third-party database host, which P1 cannot give
today. The reproducible same-origin slice is a database file the app itself serves: a
SQLite file or SQL dump returned by a GET with no credentials. A same-origin 200 whose body
carries the SQLite header or SQL-dump statements is `EXPOSED`, signed, and reportable.

## Flow

```bash
pry scan ./my-app
pry scan https://example.com --token <token>
```

Always-on level 0. Four fixed paths: `/data.db`, `/app.db`, `/db.sqlite`, `/dump.sql`.
No flag, no config, no writes.

## Scope

- One GET per path; no auth, no redirects, 4 KiB cap.
- SQLite magic (`SQLite format 3\0`) or a SQL dump signature at the start of the body.
- `EXPOSED` only for a same-origin 2xx with a signature; signed proof.
- Stored body is a short signature excerpt; the dump is never downloaded or kept.
- `NOT_REPRODUCED` for 401/403/404, an HTML fallback, or no signature; `UNVERIFIED` on
  transport.
- Tests: sidecar/parser, local/live, CLI, Docker fixture with a served SQL dump.
- Docs: request counts, DB file scope, provider rule checks deferred.

## Out of scope

- Firebase/Supabase open-rule checks; ownership of a third-party DB host.
- Database discovery, credential use, bulk download, SQL injection.
- Header policy analysis, live SSRF, live rate-limit, Level 2, hosted reports.

## Acceptance criteria

- SQLite file at `/data.db` → EXPOSED, signed, report.
- SQL dump at `/dump.sql` → EXPOSED; stored body is an excerpt, not rows.
- 404/401/403 or HTML 200 → NOT_REPRODUCED.
- Transport failure → UNVERIFIED.
- No database signature → default scan still runs all probes.
- No "secure" claim; provider rule checks stay deferred.
- Default suite offline; Docker test opt-in.
