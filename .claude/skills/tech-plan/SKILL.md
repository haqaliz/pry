---
name: tech-plan
description: Create a phased technical implementation plan from planning artifacts in docs/planning (PRD + aspect spec). Use after prd-interview when ready to execute a specific aspect. Triggers on "tech plan", "implementation plan", "plan from PRD".
tags:
  - planning
  - documentation
metadata:
  status: trial
---

Create a phased technical implementation plan from planning artifacts under `docs/planning/{slug}/`.
This is Phase 5 of `pry-begin-fast` — the plan it produces is executed in Phase 6 through the agents team under strict TDD.

If artifacts are in context, use them directly. Otherwise, search `docs/planning/*/prd.md` and
`docs/planning/*/*/spec.md`.

Pry is **greenfield**: today the authoritative reading is `docs/technical/CAPABILITY_ROADMAP.md`
(P1..P7), `docs/technical/ARCHITECTURE.md`, and `docs/ROADMAP.md`; the engine lives under
`src/pry/` once it exists.

## Handoff Contract

- **Feature requirements source:** `docs/planning/{slug}/prd.md`
- **Aspect requirements source (preferred):** `docs/planning/{slug}/{aspect}/spec.md`
- **Plan output (required):** `docs/planning/{slug}/{aspect}/plan_YYYYMMDD.md`

## Deliverables

### 1. Project Setup Checklist

Directory/module structure under `src/pry/`, `tests/`. Dependencies via `uv add`.
**Greenfield:** scaffold `pyproject.toml`/`uv.lock`/`src/` as part of the plan's first phase if
they don't exist — test-first still holds.

### 2. Implementation Phases

Goal, Prerequisites, Files to create/modify, Validation (`uv run pytest <path>`), Commit message.

### 3. File-by-File Build Order

Filepath, one-line purpose, key exports, dependencies.

### 4. Testing Strategy

Unit tests mapped to phases, written first. **Start from the capability's acceptance intent** in
`CAPABILITY_ROADMAP.md` and the aspect `spec.md`. Tests run against **fixture apps under local
sandbox control only** — never a real third-party target, even in dev. No network reachable from
any test unless it is the test's own local fixture server.

### 5. Environment & Determinism

Env vars (ownership-verification tokens and any BYOK key stay in `.env`, never committed).
`uv sync`. A finding's proof must be reconstructible from the recorded bundle alone.

### 6. Edge Cases & Error Handling

Name the explicit `UNVERIFIED` cause for anything that fails to evaluate
(`OWNERSHIP_UNVERIFIED`, `TARGET_UNREACHABLE`, `INTENSITY_INSUFFICIENT`,
`SANDBOX_BOOT_FAILED`, `PROBE_INCONCLUSIVE`). A probe that can't reach a clean conclusion is
`NOT_REPRODUCED` or `UNVERIFIED` — never upgraded to `EXPOSED` on a guess.

### 7. Agent Execution Notes

Checkpoints for human review — flag anything touching the ownership gate or an intensity-level
escalation for explicit human review before it ships, not just before it runs.

## Guidelines

- Be extremely explicit. Prefer small, testable increments.
- Don't plan work that lets a heuristic stand in for a reproduced request/response pair, or
  that lets a probe run before P1's ownership check — flag it against `CLAUDE.md`'s wedge.
- Respect the build order: P2/P3 need P1; P4 needs P3; P5 needs P3+P4 (the moat); P6 needs P5;
  P7 is deferred.

## Edge Cases

- **Greenfield vs. existing codebase**: full setup for greenfield.
- **No aspect spec exists yet**: derive candidates, ask the user to choose, draft `spec.md`.
- **Incomplete PRD**: flag it, recommend `prd-interview`.
- **PRD with flagged gaps**: note in the plan, recommend resolution before the affected phase —
  especially any gap touching the ownership gate or intensity levels.
