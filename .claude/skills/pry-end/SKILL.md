---
name: pry-end
description: Use when finishing local work on a Pry unit of work after the PR is merged and you also need a completion report on Desktop. Triggers on "pry-end", "pe", "pe bug 12", "pe feat ownership-verify", "end full".
arguments: "type id"
---

# Pry End (Full Track)

## Overview

Same cleanup as `pry-end-fast`, plus a completion report via `pry-report`.

**Invocation:** `pe <type> <id>`.

## Pipeline

**REQUIRED SUB-SKILL:** `pry-end-fast`. Run Phase 0 → Phase 2. Base branch `main`.
Phase 3 (release) deferred.

### Phase 4 — Completion report

**REQUIRED SUB-SKILL:** `pry-report`.

| `pe` arg | `pry-report` arg |
|---|---|
| `bug` | `bug` |
| `task` / `chore` | `task` |
| `feat` / `feature` | `feature` |

### Phase 5 — Comment on the issue (optional)

Skip if no reachable issue.

## Common mistakes

| Mistake | Fix |
|---|---|
| Running the report before cleanup | Phases 0–2 first |
| Cleaning up against `master` | Pry's base branch is `main` |
