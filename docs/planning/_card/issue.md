# Local IDOR (P3 remainder)

- **Type:** feat
- **Slug:** `local-idor`
- **Owner:** aliz
- **Source:** inline brief. No GitHub issue.
- **Capability:** P3 remainder — configured local IDOR/access control.

## Brief

Live IDOR is implemented. The safe sandbox path still lacks the companion check: two identities,
two objects, and a cross-request that proves identity A can read identity B's object. Run the
same three GETs inside the local probe sidecar, with the credential config mounted read-only at
0600. The result is a normal verdict: `EXPOSED` only when both controls pass and A→B returns 2xx
JSON; signed and reportable like any other finding.

## Flow

```bash
chmod 600 idor.json
pry scan ./my-app --idor-config idor.json
```

The config has the same shape as live IDOR. Pry validates it, writes a 0600 temp copy, mounts
it read-only into the probe sidecar at `/pry-config/idor.json`, runs the three GETs, parses the
redacted result, and removes the temp file. The original path and credentials never appear in
results, proofs, reports, logs, or errors.

## Scope

- Local `--idor-config` at level 0; no `--confirm` (read-only configured check).
- Reuse the live IDOR probe logic; move the core to a sidecar-callable function.
- Config 0600, temp copy 0600, read-only mount, cleanup.
- EXPOSED/NOT_REPRODUCED/UNVERIFIED with both controls; redacted auth/cookie headers.
- Signed proof/report for EXPOSED.
- Tests: sidecar, scan, CLI, Docker fixture with two identities/objects.

## Out of scope

- IDOR discovery, non-configured IDOR, live changes, DB rules, level 2/writes.
- Hosted reports.

## Acceptance criteria

- Local A→A 200, B→B 200, A→B 200 JSON → EXPOSED, signed, report.
- A→B 403 → NOT_REPRODUCED; B→B 403 → UNVERIFIED.
- Config 0644/missing/absolute paths/header injection → exit 2, no scan.
- Credentials/config path absent from outputs; temp config removed.
- No config → existing local results unchanged.
- Default suite offline; Docker test opt-in.
- No "secure" claim.
