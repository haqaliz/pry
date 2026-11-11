# Provider Database Rules with Marker Ownership (P3 remainder)

- **Type:** feat
- **Slug:** `provider-db`
- **Owner:** aliz
- **Source:** inline brief. No GitHub issue.
- **Capability:** P3 remainder — Firebase Realtime Database and Supabase REST open-rule checks.

## Brief

The last P3 read check is exposed database/open rules. P1 cannot prove ownership of a
third-party database host with DNS/well-known files, so this slice uses a marker the owner
places in the database through the provider console. `pry database --config db.json
--confirm-marker` reads the marker unauthenticated, then reads one declared data path
unauthenticated. A non-empty JSON response is `EXPOSED`, signed like any finding. The marker is
a control attestation, not a DNS-grade proof; the docs say so.

## Flow

```bash
chmod 600 db.json
pry database --config db.json --confirm-marker
```

Firebase config:

```json
{
  "provider": "firebase-rtdb",
  "url": "https://project-default-rtdb.firebaseio.com",
  "marker_path": "/.pry-ownership",
  "marker": "pry-<random>",
  "read_path": "/users"
}
```

Supabase config:

```json
{
  "provider": "supabase",
  "url": "https://project.supabase.co",
  "anon_key": "<public anon key>",
  "marker_path": "/rest/v1/pry_ownership?select=marker",
  "marker": "pry-<random>",
  "read_path": "/rest/v1/users?select=*"
}
```

## Scope

- Firebase RTDB: GET `<url><path>.json`; Supabase: GET `<url><path>` with `apikey`.
- 0600 config; HTTPS unless loopback; no userinfo; path validation.
- Marker read first; mismatch/denied/transport → exit 2, no data request.
- Data path `EXPOSED` only for a same-origin 2xx non-empty JSON body; signed proof.
- Empty body/`[]`/`{}`/`null` or 401/403/404 → `NOT_REPRODUCED`; 5xx/transport → `UNVERIFIED`.
- Supabase anon key redacted from results/proofs/errors; only the declared path is read.
- Tests: config, both providers, marker mismatch, data verdicts, redaction, loopback, CLI.
- Docs: marker limitation, anon key, no dump, no discovery, no secure.

## Out of scope

- Firestore, other providers, rule-document parsing, writes, discovery, bulk dumps.
- IDOR discovery, live SSRF, hosted reports.

## Acceptance criteria

- Firebase marker + non-empty data → EXPOSED, signed, report.
- Supabase marker + non-empty rows → EXPOSED; anon key absent from outputs.
- Marker mismatch → exit 2, no data request.
- Data 401/403/404/empty → NOT_REPRODUCED; 5xx/transport → UNVERIFIED.
- Config 0644/missing/invalid/HTTP non-loopback → exit 2.
- Only the declared path is read; body capped.
- No "secure" claim.
