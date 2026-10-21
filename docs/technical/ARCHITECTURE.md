# Pry: Architecture

Design intent, not built behavior. Nothing is implemented yet.

## Pipeline

```
target (local repo | live URL)
        |
        v
  P1 ownership verification  (DNS TXT | well-known file | account-link)
        |  (gates everything below, at every intensity, including level 0)
        v
  P2 intake  ---->  pinned snapshot (sandbox boot, or recorded live endpoint set)
        |
        v
  P3 floor probes (read-only, always on)
        |
        v
  P4 intensity-gated probes (level 1 read-only expanded, level 2 write-based, confirmed)
        |
        v
  P5 proof capture  ---->  EXPOSED | NOT_REPRODUCED | UNVERIFIED  (+ named cause)
        |
        +-->  P6 findings corpus / report
```

## Layout (planned)

```
src/pry/
  own/        P1: verification methods, proof tokens
  intake/     P2: sandbox boot, live endpoint recording
  probes/
    floor/    P3: the always-on read-only checks
    gated/    P4: level 1 and level 2 checks, confirmation flow
  proof/      P5: request/response capture, redaction, signing
  corpus/     P6: findings store, report generator
  cli/        pry scan | verify-ownership | report
tests/        offline; fixture apps under local sandbox control; no real third-party targets
```

## Key decisions

- **Ownership gate is structurally first.** Every code path that reaches a probe passes through
  P1's check; this is enforced in the type/call structure, not just documented.
- **Floor probes are read-only by construction.** Each floor check's implementation is reviewed
  for side effects (a GET that happens to trigger a webhook is not "read-only").
- **Confirmation is explicit and per-target.** Raising intensity requires a fresh confirmation for
  each target, not a global setting; a live target at level 2 requires an additional step beyond
  the standard warning.
- **Proof capture is minimal and redacted.** Only the bytes needed to demonstrate the finding are
  retained; anything beyond that is truncated or redacted before storage.
- **Determinism and replay.** A finding's proof bundle is signed and independently verifiable,
  following the pattern Plumb uses for its bundles (not shared code — reimplemented standalone).
- **UNVERIFIED causes** (draft): `OWNERSHIP_UNVERIFIED`, `TARGET_UNREACHABLE`,
  `INTENSITY_INSUFFICIENT`, `SANDBOX_BOOT_FAILED`, `PROBE_INCONCLUSIVE`.

## CLI shape (target)

`pry verify-ownership <target>` — runs the proof flow, issues a signed ownership token.
`pry scan <target> --token TOKEN [--level 0|1|2] [--confirm] [--out DIR] [--json]`

Exit 0 on `NOT_REPRODUCED`/clean, 1 on any `EXPOSED`, 2 on usage or ownership failure. Never a
traceback.

## Open questions

- Sandbox boot strategy per target framework (Node/Next, Python, static) for local-repo intake.
- Whether a crypto-subscription hosted tier needs its own service component, or stays CLI-only
  with a license-key check — decide once Phase 3 is reached.
- PyPI distribution name: `pry` is taken; `pryhq` was free when checked.
