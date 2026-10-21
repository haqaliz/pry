---
name: pry-next
description: Use when deciding what to build next in Pry and you want the single highest-leverage capability picked from the repo's own roadmap and planning files (not invented), grounded in the moat and in what has already shipped or been deferred, ending with a ready-to-run handoff. Triggers on "pry-next", "pn", "what's next", "next feature", "pick next".
arguments: ""
---

# Pry Next (pick the most important capability)

## Overview

Read the repo's own roadmap and planning files, rank the real candidate capabilities
against the moat and against what has shipped or been deferred, and recommend the
single highest-leverage one to build next. End with a ready-to-paste
`pry-begin-fast` invocation.

This skill RECOMMENDS and hands off. It does NOT create a worktree itself.

## When to use

- "what should I build next", at the start of a session.
- Not for: executing a chosen capability (use `pry-begin-fast`), or planning an
  already-chosen one (use `prd-interview` / `tech-plan`).

## The candidate set is the FILES, never invented

- `docs/technical/CAPABILITY_ROADMAP.md`: the **P1..P7** engine capabilities in
  build order. The primary candidate set.
- `docs/ROADMAP.md`: the phases, milestones, and **R1..R7 risk register**.
- `CLAUDE.md` and `VISION.md`: the wedge, the moat, the guardrails — especially
  the ownership gate and the no-"secure"-verdict rule.
- `docs/technical/ARCHITECTURE.md`: the own → intake → probe → prove → report design.
- `docs/planning/*/`: in-flight, completed, and deferred work, once any exists.
- `git log` / the test suite: what actually shipped. **Today there are no commits
  beyond the scaffold** — say so plainly.

## How to rank (grounded in CLAUDE.md)

1. **Ownership verification (P1) is structurally first.** No candidate that lets a
   probe run before P1 gates it, at any intensity, is acceptable.
2. **Execution-grounded proof only.** A candidate that lets a heuristic stand in
   for a reproduced request/response pair is dropped.
3. **Respect the build order.** P2/P3 need P1; P4 needs P3; P5 is the moat and
   needs P3+P4; P6 needs P5; P7 is deferred (needs partnerships).
4. **Read-only before write-based.** Within P3/P4, a read-only check always ships
   before the write-based confirmation flow it depends on.
5. **The gate beats the feature.** Before Phase 0's gate (ownership verification
   works, ETHICS.md exists, no probe code without it), that gate is the priority.

## Process

1. Read the files above. Build the candidate list.
2. For each candidate: shipped-state (cite the file), dependency status,
   moat-leverage, the risk it retires (by R-id), any known blocker.
3. Rank. Pick ONE, plus one or two alternates.
4. Sanity-check against the guardrails — especially: does this candidate ever run
   a probe before ownership is proven, and does it ever imply "secure"?
5. Produce the handoff.

## Output format

- **The pick**: one line naming the capability (with its P-id) and a kebab-case slug.
- **Why**: 2 to 3 bullets.
- **Alternates.**
- **Known caveat**: nearest feasibility/ethics risk (R-id).
- **Handoff prompt**: a `pbf feat <slug>` line plus a 3 to 5 sentence brief,
  including the capability's acceptance tests.

## Honesty rules

- Ground every claim in a named file. Say "not started" rather than implying progress.
- Never recommend work that would let intensity rise, or a probe run, without the
  ownership gate already in place.

## Common mistakes

| Mistake | Fix |
|---|---|
| Inventing a capability not in the docs | The candidate set is P1..P7 |
| Recommending a probe capability before P1 ships | P1 gates everything, including read-only |
| Recommending write-based checks before read-only ones exist | Respect the intensity-level order |
| Reaching for P7 (platform integration) early | Needs partnerships; not scheduled |
| Starting the worktree from this skill | Only recommend; the user runs `pbf` |
