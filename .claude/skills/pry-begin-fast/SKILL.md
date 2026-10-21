---
name: pry-begin-fast
description: Use when starting work on a Pry unit of work (a GitHub issue id or an inline brief) and you want the fast path straight to an implementation plan. Triggers on "pry-begin-fast", "pbf", "pbf bug 12", "pbf feat ownership-verify", "begin fast".
arguments: "type id"
---

# Pry Begin (Fast Track)

## Overview

Turn a single unit of work into shipped, test-driven code. The fast track is:
**isolate → gather → dig → PRD → plan → implement (TDD).** No proposal/diagram
deliverables (use `pry-begin` / `pb` when you need those).

**Two non-negotiables:** always work through the agents team; implementation is
always test-first via `superpowers:test-driven-development`.

**Invocation:** `pbf <type> <id>` — e.g. `pbf bug 12`, `pbf feat ownership-verify`.

- `type` ∈ `bug | feat | feature | task | chore`.
- `id` = a GitHub issue number or a short descriptive slug.
- Owner is `aliz`.

## Task source: GitHub issue, tolerate absence

Pry's remote does not exist yet. Expect the fallback inline-brief path.

## Pipeline

### Phase 0 — Isolate in a worktree

**REQUIRED SUB-SKILL:** `pry-worktrees`. Branch `<type>/<id>/aliz`, worktree dir
`.claude/worktrees/<type>-<id>`, created from `main` (no remote yet).

### Phase 1 — Gather context

Save a raw dump to `docs/planning/_card/issue.md`. If no issue, write the brief.

### Phase 2 — Deep dig

- Map the relevant code paths. Pry is **greenfield** — today that means
  `docs/technical/CAPABILITY_ROADMAP.md` (P1..P7), `docs/technical/ARCHITECTURE.md`,
  `docs/ROADMAP.md`. Once the engine exists it lives under `src/pry/`.
- Honor `CLAUDE.md`: **ownership is proven before anything runs, at every
  intensity level, including the lowest.** No code path may reach a probe without
  passing through P1. No verdict may claim "secure" — only `EXPOSED` /
  `NOT_REPRODUCED` / `UNVERIFIED` exist. Destructive or write-based checks require
  explicit, per-target, per-level confirmation.
- Place the work in the pipeline (P1 ownership, P2 intake, P3 floor probes, P4
  intensity-gated probes, P5 proof/verdict, P6 corpus/report, P7 platform
  integration).

### Phase 3 — Requirements interview

**REQUIRED SUB-SKILL:** `prd-interview`. Confirm a descriptive kebab-case slug.

### Phase 4 — Generate & self-critique the PRD

**REQUIRED SUB-SKILL:** `prd-generator`.

### ⛔ Review gate — STOP

### Phase 5 — Implementation plan

**REQUIRED SUB-SKILL:** `tech-plan`.

### Phase 6 — Implement (TDD, agents team)

**REQUIRED SUB-SKILL:** `superpowers:test-driven-development`,
`superpowers:subagent-driven-development`.

- `uv run pytest` after each task. Tests use fixture apps under local sandbox
  control only — **never a real third-party target**, even in dev.
- Commit per task on `<type>/<id>/aliz`.

## Artifact layout

```
docs/planning/
├── _card/issue.md
├── {slug}/prd.md
└── {slug}/{aspect}/plan_*.md
```

## Common mistakes

| Mistake | Fix |
|---|---|
| Working in the primary checkout | Create the Phase 0 worktree first |
| Branching from anything but `main` | No remote exists yet; use local `main` |
| Treating a missing `pyproject.toml` as fatal | Greenfield — scaffold it, test-first |
| Skipping the review gate | PRD must be approved before tech-plan |
| Planning a probe that could run before ownership verification | Stop and flag — P1 gates everything |
| Implying a verdict of "secure" anywhere in the plan | Never — only `EXPOSED`/`NOT_REPRODUCED`/`UNVERIFIED` exist |
