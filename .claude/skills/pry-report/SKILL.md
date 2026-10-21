---
name: pry-report
description: Use when a Pry unit of work (bug, task, feature) is done and you want a brief, friendly, non-technical completion note saved on Desktop to share with the team.
allowed-tools: Read, Grep, Glob, Bash, Write
arguments: "type id"
---

# Pry Completion Note

## Arguments

- `type` ∈ `bug | task | feature`
- `id` = the GitHub issue number, or the slug used at begin time

Usage: `/pry-report bug 12` or `/pry-report feature ownership-verify`.

## Output

Markdown file saved to `/Users/aliz/Desktop/{type}-{id}-completion.md`.

## The template

```markdown
## #{id} - {Feature or area} - {Short Title}

Hey! Quick note that this one's {verb}.

**What changed (in plain words):**
{One or two friendly sentences. No jargon. No em dashes.}

**See it live:** {link to the PR, or the CLI command}
**Screenshot/video:** {attached, or link}

If anything looks off or you'd like a tweak, just say the word.
```

Verb per type: `bug → fixed`, `task → done`, `feature → shipped`.

## Tone rules

- Plain English. Swap *ownership verification, intensity level, floor probe,
  proof capture, reproduced exploit* for everyday phrasing. "Proves it really
  broke, and keeps the proof" beats "exploit-verified proof capture."
- No checklists, no commit hashes, no file paths. **Never use the em dash `—`.**

## Don't over-claim (this one matters here, more than anywhere else)

- **Never say an app is "secure" or "safe."** If nothing was found, say "we
  couldn't reproduce an issue this time" — not "it's secure."
- Say exactly what was proven: a real request that returned data it shouldn't
  have, not a guess.
- Always name the ownership step if it's relevant — never imply a scan ran
  against anything the user didn't prove they control.

## Workflow

1. **Get the context.** `gh issue view` / `gh pr view`, or the session's own work.
2. **Distill** into one or two plain sentences.
3. **Pick the "See it live" target**: the PR, or the CLI command
   (`uv run pry scan <target> --token TOKEN`).
4. **Ask for a screenshot or short video** — redact anything sensitive first.
5. **Write** the note.

## Example (feature)

```markdown
## #34 - Scanner - Prove an exposed endpoint, not just guess at one

Hey! Quick note that this one's shipped.

**What changed (in plain words):**
Pry can now check an app you own for a few common mistakes, like a page that
should ask for a login but doesn't. It only tries this on apps you've proven
are yours, and it only reports something as a problem when it actually got
back data it shouldn't have. No login page to check? It says so honestly,
instead of guessing.

**See it live:** run `uv run pry scan <target> --token TOKEN`
**Screenshot/video:** attached (redacted)

If anything looks off or you'd like a tweak, just say the word.
```
