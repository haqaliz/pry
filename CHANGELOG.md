# Changelog

All notable changes to Pry are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-11-12

First public release. PyPI package: `pry-scanner`; CLI: `pry`.

### Added

- **Ownership gate (P1):** DNS TXT and well-known-file verification; no live request without a
  valid token.
- **Local intake (P2):** static and npm Node/Next repositories boot in an isolated Docker
  sandbox with a pinned snapshot and no run-phase egress.
- **Read-only floor probes (P3):** CORS with credentials, verbose error leakage, exposed secret
  files, served SQLite/SQL-dump files, declared unauthenticated endpoints, configured live and
  local IDOR, and opt-in response-header observations.
- **Live read-only scans:** P1-gated GET-only probes against a live origin.
- **SSRF (P4, Level 1):** local callback sidecar and live user-supplied callback with a nonce
  poll contract; `EXPOSED` only on a callback hit.
- **Rate-limit observations (P4, Level 1):** bounded local/live samples; unsigned, never
  `EXPOSED`, stop on the first throttle.
- **Level 2 write confirmation (P4):** one declared write plus a marker verification read;
  local sandbox by default, live only with `--confirm-live-write`; no rollback.
- **Provider database checks (P3):** Firebase RTDB and Supabase REST open-rule checks using a
  user-placed marker; 0600 config, `--confirm-marker`, anon key redaction, one data path capped
  at 4 KiB.
- **Signed proof bundles (P5):** Ed25519 bundles for every `EXPOSED` finding, offline
  verification, fingerprint pinning, and `pry replay` for read-only live proofs.
- **Reports and corpus (P6):** local HTML report and JSONL findings corpus; database checks are
  reportable too.
- **CI action:** a composite GitHub Action for local repository scans; fails the job on
  `EXPOSED`.

### Security and safety

- No `SAFE`/`SECURE` verdict exists. A clean result is `NOT_REPRODUCED`, never "secure."
- Live scans require a P1 token; Level 1 and Level 2 require explicit confirmation.
- Credentials and configs are 0600, mounted read-only where applicable, and redacted from
  results, proofs, reports, logs, and errors.
- Database rows, secret values, and proof bodies are minimized or redacted.

### Not in 0.1.0

- IDOR discovery and endpoint discovery (deliberate: no guessing).
- Hosted/public reports and platform partnerships (P7).
- A published real-world case study (M1.4).

[0.1.0]: https://github.com/haqaliz/pry/releases/tag/v0.1.0
