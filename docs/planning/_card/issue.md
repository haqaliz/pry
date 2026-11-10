# Live Level 2 Write Confirmation (P4 remainder)

- **Type:** feat
- **Slug:** `live-writes`
- **Owner:** aliz
- **Source:** inline brief. No GitHub issue.
- **Capability:** P4 — live write confirmation with an extra explicit confirmation.

## Brief

Local Level 2 writes are implemented. The live path still rejects writes. Constraint 6 permits
a live write only when the owner explicitly raises the intensity with a full warning; the
roadmap requires an extra step beyond the standard confirmation. This slice adds
`--confirm-live-write`: one declared POST/PUT/PATCH against a P1-verified origin, a unique
marker, and a verification read. It is still signed only when the write is 2xx and the marker is
read back.

## Flow

```bash
chmod 600 write.json
pry scan https://staging.example.com --token <token> \
  --level 2 --confirm --confirm-live-write --write-config write.json
```

The write runs from the host in-process, not in a sandbox. Use a staging copy or a disposable
test record; Pry does not roll back a live write.

## Scope

- Live `--level 2 --confirm --confirm-live-write --write-config FILE` + P1 token.
- Same config and marker verification as local Level 2.
- One write + one verification GET; no DELETE, uploads, auth, or multi-step workflows.
- `EXPOSED` only for write 2xx + verify 2xx + marker; signed and reportable.
- The extra flag is required; without it the live write exits 2 before any request.
- Tests: live scan, CLI gate, loopback integration, no real third-party target.
- Docs/ETHICS: full warning, staging preference, no rollback, live write risk.

## Out of scope

- DELETE, uploads, auth, multi-step workflows, rollback.
- IDOR discovery, provider DB rules, live SSRF, hosted reports.
- Writing to a target without a P1 token.

## Acceptance criteria

- Live level 2 + token + both confirmations + config → one `write` result.
- Write 201 + verify 200 marker → EXPOSED, signed, report.
- Write 401/403/404 or marker absent → NOT_REPRODUCED.
- Missing `--confirm-live-write` → exit 2, no request.
- Missing token / invalid config / SSRF flags → exit 2, no request.
- No DELETE; no config path in outputs.
- Docs state staging preference, no rollback, and the live write risk.
