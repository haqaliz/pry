# Live Proof Replay (P5 remainder)

- **Type:** feat
- **Slug:** `live-replay`
- **Owner:** aliz
- **Source:** inline brief. No GitHub issue.
- **Capability:** P5 — replay a signed read-only proof against its P1-verified live target.

## Brief

A signed proof is only useful if the owner can check that the saved request still reproduces.
`pry replay BUNDLE --token TOKEN` verifies the bundle, proves ownership of the live target
again, re-sends the recorded GET with no credentials and no redirects, and reports whether the
response status still matches. It is a replay check, not a new verdict or proof.

## Flow

```bash
pry replay ~/.pry/runs/<id>/proofs/<bundle_id>.json \
  --token <token>
```

Output: `MATCH`, `MISMATCH`, or `UNVERIFIED`, with the recorded and replay statuses. Exit 0
match, 1 mismatch, 2 invalid/unverified.

## Scope

- Valid signed bundle required; optional `--fingerprint` pin.
- Live target only; finding method GET only; same-origin request URL.
- P1 token for the bundle target, validated before any request.
- Re-send only `User-Agent`/`Accept` from the recorded headers; no auth/cookie/API key.
- No redirects, 5s timeout, 4 KiB cap.
- Status-only comparison; probe-specific conditions are not re-evaluated.
- `--json`; no new proof, no token stored.
- Tests: loopback match/mismatch/transport, invalid bundle, non-live, non-GET, wrong token,
  header filtering, JSON.
- Docs: what replay does and does not prove.

## Out of scope

- Local/sandbox replay, write replay, probe-specific re-evaluation, new proof signing.
- IDOR discovery, provider DB rules, live SSRF, hosted reports.

## Acceptance criteria

- Valid live GET proof + correct token + same status → MATCH, exit 0.
- Different status → MISMATCH, exit 1.
- Transport failure → UNVERIFIED, exit 2.
- Invalid bundle/fingerprint → exit 2, no request.
- Local bundle, non-GET finding, or foreign request URL → exit 2, no request.
- Wrong-target/missing token → exit 2, no request.
- Authorization/Cookie are never sent; token never stored.
- No "secure" claim.
