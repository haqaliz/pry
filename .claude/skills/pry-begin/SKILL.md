---
name: pry-begin
description: Use when starting work on a Pry unit of work (a GitHub issue id or an inline brief) and you need stakeholder proposals (technical + non-technical PDFs with diagrams) before planning. Triggers on "pry-begin", "pb", "pb bug 12", "pb feat ownership-verify", "begin full".
arguments: "type id"
---

# Pry Begin (Full Track)

## Overview

Same pipeline as `pry-begin-fast`, plus a **proposal phase**: diagrams and two
review PDFs for stakeholders, then an approval gate, then planning.

**Invocation:** `pb <type> <id>`.

## Pipeline

**REQUIRED SUB-SKILL:** Use `pry-begin-fast` for the base pipeline.

Run its **Phase 0 → Phase 4 and the ⛔ PRD review gate exactly as written.**

### Phase A — Proposals (diagrams → PDFs)

See `references/proposals.md`.

1. **Diagram** — `excalidraw`, saved to `docs/planning/{slug}/diagrams/*.excalidraw`.
2. **Export** — `excalidraw-to-svg`.
3. **Write two proposals** in `docs/planning/{slug}/proposals/`.
4. **PDF** — `md-to-pdf`.

### ⛔ Approval gate — STOP

### Final phases — Plan & implement

Run `pry-begin-fast`'s **Phase 5** then **Phase 6**.

## Artifact layout

```
docs/planning/
├── _card/issue.md
├── {slug}/prd.md
├── {slug}/diagrams/*.excalidraw|.svg
├── {slug}/proposals/<type>-<id>-technical-proposal.{md,pdf}
├── {slug}/proposals/<type>-<id>-non-technical-proposal.{md,pdf}
└── {slug}/{aspect}/plan_*.md
```

## Common mistakes

| Mistake | Fix |
|---|---|
| Writing proposals before the PRD is approved | Phase A starts only after the first ⛔ gate |
| One proposal for both audiences | Always two |
| Implying a verdict of "secure" in either proposal | Never — only `EXPOSED`/`NOT_REPRODUCED`/`UNVERIFIED` exist |
| Diagramming a probe running before ownership verification | P1 gates everything — show it that way |
