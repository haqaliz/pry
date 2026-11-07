# Configured IDOR Checks (P3 remainder, live)

- **Type:** feat
- **Slug:** `idor-live`
- **Owner:** aliz
- **Source:** inline brief. No GitHub issue.
- **Capability:** P3 remainder — IDOR/access control, live configured slice. Depends on P1,
  the live read-only path, P5 bundles, P6 report, and `ETHICS.md`.

## Brief

The missing-auth check covers a declared protected endpoint. IDOR is the companion: a user
who is allowed to see object A must not be able to see object B. This slice takes a local
config with two identities and two object paths, runs three read-only GETs on a live target,
and reports `EXPOSED` only when identity A can read B's object while both controls succeed.

No discovery, no local IDOR, no writes. The config holds session cookies/tokens, so it must be
0600 and must never appear in results, proofs, reports, logs, or errors.

## Config

```json
{
  "identity_a": {"headers": {"Cookie": "session=a"}},
  "identity_b": {"headers": {"Cookie": "session=b"}},
  "object_a": "/api/items/1",
  "object_b": "/api/items/2"
}
```

- File mode 0600; group/other bits → refuse.
- Paths are path-only (start `/`, no `://`, no `//`, no whitespace).
- Headers: non-empty names/values, no control characters/newlines, no `Host`,
  `Content-Length`, or `Transfer-Encoding`.
- The config path is not included in results/proofs/reports.

## Probe

1. `GET object_a` with identity A → must be 2xx JSON/non-empty (control A).
2. `GET object_b` with identity B → must be 2xx JSON/non-empty (control B).
3. `GET object_b` with identity A → if 2xx JSON/non-empty, `EXPOSED`; 401/403/404,
   `NOT_REPRODUCED`; 5xx/transport, `UNVERIFIED`.

If either control fails, `UNVERIFIED` with `IDOR_CONTROL_FAILED`; the cross request is not
used to claim exposure. Request/response headers are redacted (`Cookie`, `Authorization`,
`Set-Cookie`, `X-Api-Key`, etc.) before the result is stored.

## Scope

- `pry scan URL --token TOKEN --idor-config FILE` (live only).
- `--report`/`--json` include the IDOR result; signed proof for EXPOSED.
- A local path with `--idor-config` → exit 2, `IDOR_REQUIRES_LIVE`.
- Tests: config validation, verdicts/controls, redaction, CLI, loopback integration.

## Out of scope

- Local/sandbox IDOR (credential transport), discovery, exposed database rules.
- P4/levels 1–2, writes, hosted reports.
- Claims about objects not in the config.

## Acceptance criteria

- A→A 200, B→B 200, A→B 200 JSON → `EXPOSED`, signed, report written.
- A→B 403 → `NOT_REPRODUCED`; B→B 403 → `UNVERIFIED`.
- Config 0644 / absolute object path / header injection → exit 2, no request.
- Credentials absent from results, proofs, report, logs; token absent too.
- Config path absent from outputs.
- Default suite offline; loopback integration only; no Docker.
- No "secure" claim.
