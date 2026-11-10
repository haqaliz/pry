# Local Level 2 Write Confirmation (P4 remainder)

- **Type:** feat
- **Slug:** `level2-writes`
- **Owner:** aliz
- **Source:** inline brief. No GitHub issue.
- **Capability:** P4 — declared unauthenticated write confirmation in the local sandbox.

## Brief

Level 2 exists in the roadmap but nothing runs. The safe first slice is local-only: the owner
declares one write that should require auth, Pry sends it with no credentials inside the
disposable sandbox, then reads a declared verification path. `EXPOSED` only when the write is
accepted and the verification read contains the unique marker that Pry generated. Live writes
stay rejected.

## Flow

```bash
chmod 600 write.json
pry scan ./my-app --level 2 --confirm --write-config write.json
```

`write.json`:

```json
{
  "method": "POST",
  "endpoint": "/api/items",
  "body": "{\"name\": \"{{marker}}\"}",
  "verify_endpoint": "/api/items",
  "verify_contains": "{{marker}}"
}
```

Pry replaces `{{marker}}` with a fresh `pry-<hex>` value, sends the write unauthenticated, then
GETs the verification path. The write response is the captured pair; the verification request
and response are nested under `response.verification` in `results.json` and the signed proof.

## Scope

- Local `--level 2 --confirm --write-config FILE`; config 0600.
- Methods POST/PUT/PATCH only; path-only endpoints; 4 KiB body cap; no auth.
- `EXPOSED` only for write 2xx + verify 2xx + unique marker in the verify body.
- Write rejected (401/403/404) or marker absent → `NOT_REPRODUCED`; transport/write 5xx →
  `UNVERIFIED`.
- Temp config 0600, read-only mount, removed on every path.
- Signed proof and report for `EXPOSED`.
- Docker fixture with an unauthenticated write and a verification read.
- Docs: local-only, marker, live writes deferred, no secure.

## Out of scope

- Live writes, DELETE, file uploads, auth, multi-step workflows.
- IDOR discovery, provider DB rules, live SSRF, hosted reports.
- Discovery of write endpoints.

## Acceptance criteria

- POST 201 + GET 200 containing the marker → EXPOSED, signed, report.
- Write 401/403/404 → NOT_REPRODUCED.
- Write 2xx but marker absent → NOT_REPRODUCED.
- Write 5xx or transport → UNVERIFIED.
- Level 2 without `--confirm` or `--write-config` → exit 2, no scan.
- Config 0644/missing/invalid/absolute path/`{{marker}}` absent → exit 2, no scan.
- Live URL with `--write-config` → exit 2, no request.
- Config path/body secrets absent from outputs; temp config removed.
- No "secure" claim.
