# PRD — Provider Database Rules with Marker Ownership (P3 remainder)

- **Status:** Approved on standing instruction (2026-11-11)
- **Owner:** aliz
- **Slug:** `provider-db`
- **Capability:** P3 — Firebase RTDB / Supabase REST open-rule checks

## Problem Statement

Vibe-coded apps often ship with a Firebase Realtime Database or Supabase project whose read
rules allow anyone to read data. P1 cannot verify ownership of `*.firebaseio.com` or
`*.supabase.co`: the user does not control those DNS zones. The honest alternative is a marker
the owner places in the database through the provider console. Reading the marker proves the
declared project is under the user's control; reading a declared data path proves public read.

## Goals & Success Metrics

1. `pry database --config db.json --confirm-marker` reads a marker and one data path.
2. Marker mismatch/denial/transport exits 2 before the data request.
3. `EXPOSED` only for a same-origin 2xx non-empty JSON data response; signed and reportable.
4. Supabase anon key and config path never appear in results/proofs/errors.
5. Only the declared path is read; the body is capped; no dump.

## Requirements

| ID | Requirement |
|---|---|
| M1 | 0600 JSON config; `provider` in `firebase-rtdb`/`supabase`; `url`, `marker_path`, `marker`, `read_path`; `anon_key` for Supabase. |
| M2 | HTTPS required unless the host is loopback; no userinfo; Firebase paths have no query/fragment; query allowed only for Supabase. |
| M3 | Marker read first: Firebase JSON string or `{"marker": ...}`; Supabase list/dict row with `marker` equal. |
| M4 | Marker mismatch, 401/403/404, 5xx, or transport → exit 2, no data request. |
| M5 | Data read with no credentials (Firebase) or `apikey` (Supabase); same-origin 2xx non-empty JSON → EXPOSED. |
| M6 | Empty `{}`/`[]`/`""`/`null`, non-JSON, 401/403/404 → NOT_REPRODUCED; 5xx/transport → UNVERIFIED. |
| M7 | Sign EXPOSED; store the marker pair under `response.ownership`; redact `apikey`; no config path. |
| M8 | CLI `pry database --config FILE --confirm-marker [--out] [--json]`; exit 1 EXPOSED, 0 otherwise, 2 config/ownership. |
| M9 | Tests: config, both providers, marker/data verdicts, redaction, loopback, CLI, docs. |

## Technical Considerations

- `src/pry/probe/database_rules.py`: `DatabaseConfig`, `load_database_config`,
  `probe_database_rules(config, fetch=None)`.
- Reuse `urllib_fetch`/`TransportError`/`Response` from `sidecar.py` (host-side).
- Marker JSON parsing; data JSON parsing; 4 KiB cap; no redirects.
- Build a `database`-kind snapshot and call `finalize_results` so the proof/corpus path is
  shared.
- CLI `cmd_database`; `--out` run dir; `--json`.
- Report: treat `kind == "database"` like a live target (URL/ownership proof).
- No new dependencies; Python 3.9.

## Risks

| Risk | Severity | Mitigation |
|---|---|---|
| **Marker is weaker than DNS ownership.** | High/High | Explicit `--confirm-marker`; docs say it is a control attestation, use a project you own. |
| **Supabase anon key leaks.** | High/High | 0600 config; never in results/proofs/logs; redact `apikey`. |
| **Bulk data capture.** | Med/High | One declared path; 4 KiB cap; no discovery/dump. |
| **Read-open marker but protected data.** | Med/Med | Marker success only gates the data attempt; data 403 is NOT_REPRODUCED. |
| **Open-write project makes the marker weak.** | Med/Med | The data read still proves public read; docs state the limitation. |
| **Plain HTTP leaks the anon key.** | High/High | HTTPS required except loopback tests. |

**Hard question:** a marker in an open-write database is not proof of ownership. The user must
confirm they own the project; the command is explicit and the docs say the marker is not a
DNS-grade proof.

## Out of Scope

- Firestore, other providers, rule-document parsing, writes, discovery, bulk dumps.
- IDOR discovery, live SSRF, hosted reports.

## Acceptance Tests

| ID | Test | Expected |
|---|---|---|
| AT1 | Firebase marker + data | EXPOSED, signed, report |
| AT2 | Supabase marker + rows | EXPOSED; key redacted |
| AT3 | Marker mismatch | exit 2, no data request |
| AT4 | Marker 403/transport | exit 2, no data request |
| AT5 | Data 401/403/404/empty/non-JSON | NOT_REPRODUCED |
| AT6 | Data 5xx/transport | UNVERIFIED |
| AT7 | Config 0644/missing/invalid/HTTP | exit 2 |
| AT8 | Loopback both providers | EXPOSED, proof verifies |
| AT9 | Docs | marker limitation, key, no dump, no secure |

## Self-Critique

- 🟡 **The marker is an explicit weaker ownership proof.** That is the trade for covering
  third-party DB hosts; the command says so.
- 🟡 **One declared path is not a database audit.** Say so.
- 🟢 **A non-empty JSON body with no credentials is a reproduced read exposure.**
