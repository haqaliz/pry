---
name: pry-worktrees
description: Isolate parallel work in the Pry repo using the Claude Code worktree layout. Use when starting a new bug/feature that should not collide with another running Claude session. Covers branch naming, worktree placement under .claude/worktrees, per-worktree uv setup, and cleanup.
allowed-tools: Bash, Read, Write, Edit, Glob
---

# Pry Worktree Workflow

## When to Use

- Another Claude session is running on a different branch in Pry.
- You want to run two branches side by side.
- The primary checkout is dirty and switching branches would mix work.

## Layout

```
/Users/aliz/dev/at/pry/                                    ← primary (main)
/Users/aliz/dev/at/pry/.claude/worktrees/bug-12/
/Users/aliz/dev/at/pry/.claude/worktrees/feat-ownership-verify/
```

Verify ignore status: `git check-ignore -v '.claude/worktrees/'` (keep the trailing slash).

## Branch naming convention

`<type>/<id>/<owner>` — owner is `aliz`.

- `bug/12/aliz`
- `feat/ownership-verify/aliz`

Worktree dir drops the slashes: `<type>-<id>`.

## The base branch is `main`

Pry's base branch is **`main`**. The remote (`git@github.com:haqaliz/pry.git`)
**does not exist yet**. Branch from local `main` until a remote exists:

```bash
git worktree add -b feat/ownership-verify/aliz .claude/worktrees/feat-ownership-verify main
# once a remote exists:
git fetch origin main
git worktree add -b feat/ownership-verify/aliz .claude/worktrees/feat-ownership-verify origin/main
```

## Creating a worktree

```bash
git worktree add .claude/worktrees/feat-ownership-verify feat/ownership-verify/aliz
# or
claude --worktree feat-ownership-verify   # names the branch worktree-feat-ownership-verify;
                                            # create your own branch first for issue/slug naming
```

## Auto-copying gitignored config (`.worktreeinclude`)

No secrets exist yet. Once a `.env` exists (ownership-verification tokens, any
model-assist key), create `.worktreeinclude` and copy manually for bare
`git worktree add`.

**Never copy captured proof bundles, ownership tokens, or sandboxed target state
between worktrees** — they're tied to the run and target that produced them, and
copying an ownership token across contexts is exactly the kind of mistake the
ownership gate exists to prevent.

## Per-worktree setup (Python core — uv)

```bash
cd .claude/worktrees/feat-ownership-verify
uv sync
uv run pytest
uv run pry --help
```

⚠️ **Greenfield caveat:** no `pyproject.toml` yet. If your work *is* the
scaffolding, the failing test comes first.

## Switching between worktrees

```bash
git -C /Users/aliz/dev/at/pry worktree list
```

## Cleaning up

```bash
git -C /Users/aliz/dev/at/pry worktree remove .claude/worktrees/feat-ownership-verify
git -C /Users/aliz/dev/at/pry branch -d feat/ownership-verify/aliz
```

## Common pitfalls

| Symptom | Cause | Fix |
|---|---|---|
| `invalid reference: origin/main` | No remote yet | Branch from local `main` |
| Branching from `master` | Pry's base branch is `main` | Use `main` |
| `uv sync` fails: no `pyproject.toml` | Greenfield | Scaffold test-first, or skip for docs-only work |
| `git worktree add` fails: "already checked out" | Branch checked out elsewhere | `git checkout main` there, retry |
