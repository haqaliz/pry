---
name: pry-end-fast
description: Use when finishing local work on a Pry unit of work after the PR is merged and you want to clean up without generating a completion report. Triggers on "pry-end-fast", "pef", "pef bug 12", "pef feat ownership-verify", "end fast".
arguments: "type id"
---

# Pry End (Fast Track)

## Overview

Closes out local state after the PR merged: **master → pull → remove worktree →
delete branch**, with release deferred. No report (use `pry-end` / `pe` for that).

**Invocation:** `pef <type> <id>`.

Pry's base branch is **`master`**.

## Pipeline

### Phase 0 — Safety check

- Worktree clean: `git -C <worktree> status --porcelain` empty.
- Branch merged; `git branch -d` refuses otherwise — don't bypass with `-D` without OK.

### Phase 1 — Main, pulled

```bash
PRIMARY=$(git worktree list | head -1 | awk '{print $1}')
git -C "$PRIMARY" checkout master
git -C "$PRIMARY" pull --ff-only origin master
```

### Phase 2 — Remove worktree, delete branch

```bash
git -C "$PRIMARY" worktree remove ".claude/worktrees/<type>-<id>"
git -C "$PRIMARY" branch -d "<type>/<id>/aliz"
```

### Phase 3 — Release (DEFERRED)

**Pry has no release machinery yet.** Cleanup ends at Phase 2. When it lands:
`feat` → minor, `bug`/`chore`/`task` → patch; CI green before tagging; tag and
push to trigger the workflow; verify each channel before calling it done.
Release identity: **haqaliz**. PyPI name: `pry` taken, `pryhq` free when checked.
If the crypto-subscription hosted tier (Phase 3 of `docs/ROADMAP.md`) ever ships,
its own release/licensing rules get written then, not guessed here.

### Phase 4 — Comment on the issue (optional)

Ask first, draft, confirm, then `gh issue comment`.

## Common mistakes

| Mistake | Fix |
|---|---|
| Checking out / pulling `master` | Pry's base branch is `master` |
| Using `git pull` | Use `--ff-only` |
| Forcing branch delete | Only after explicit user OK |
| Cutting a release | Deferred |
