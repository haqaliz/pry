---
name: prd-interview
description: Conduct a collaborative product requirements interview between PM and engineering. Use when turning a brief or feature idea into a structured PRD and aspect-level specs through guided discovery and pressure-testing. Triggers on "prd interview", "requirements interview", "prd-interview".
tags:
  - documentation
  - planning
metadata:
  status: trial
---

# PRD Interview

Conduct a structured product requirements interview to turn a brief or feature idea into a complete PRD.
This is a collaborative exercise — the PM hat brings product context, the engineering hat brings technical reality.
Challenge assumptions. Pressure-test scope. Document what survives.

Do not create files until the Document phase.
If the tool supports a read-only or plan mode, switch to it now.

## Context

This skill is the first step in the brief-to-code pipeline (it's Phase 3 of `pry-begin-fast`).
Output is a structured PRD plus aspect-level specs that feed directly into `tech-plan`.

**Pry guardrail:** before documenting, sanity-check the work against `CLAUDE.md`. The moat is
reproducing a real exploit against an app you own and capturing the proof — read-only by
default, graduated intensity with explicit confirmation, ownership proven before anything runs.
It is **not** a pattern-matching scanner and it **never** asserts "secure." If requirements
drift toward a heuristic deciding `EXPOSED`, or toward running a probe before ownership is
proven, or toward implying safety, flag it in the interview, not after.

## Discover & Challenge

Read the user's input. Read key files: Pry is **greenfield** — today that means
`docs/technical/CAPABILITY_ROADMAP.md` (P1..P7), `docs/technical/ARCHITECTURE.md`, and
`docs/ROADMAP.md`, plus `src/pry/` once it exists.

Then pressure-test. Do not soften these.

- "What happens if we don't build this?"
- "Imagine this launched 6 months ago and failed. What went wrong?"
- "What are we choosing NOT to build if we build this?"
- For anything touching probes: "could this run, or even partially run, against a target the
  user hasn't proven they own?"

Fill remaining gaps with focused questions, 2-3 at a time:

- **Users & Problem**: Who has this problem? Cost of the status quo?
- **Success**: How measured? Target numbers?
- **Scope**: Explicitly out of scope?
- **Requirements**: Must/should/nice?
- **Technical Fit**: Which capability (`P1`..`P7`) and phase? Dependencies built?
- **Verdict and safety impact**: Does this keep ownership verification as a hard gate at every
  intensity level? Is the default read-only? Does raising intensity require explicit,
  per-target confirmation? Does any output ever imply "secure" or "safe"?

**Stop when** the problem is clear, success metrics are measurable, must-haves have testable
criteria, out-of-scope is explicit, and major technical/ethical risks are identified.

## Confirm

Summarize and confirm the feature slug (kebab-case, e.g. `ownership-verify`). Do not name the
slug `<type>-<id>`.

## Document

**Filename:** `prd.md`
**Location:** `docs/planning/{slug}/`.

```
docs/planning/{slug}/
├── prd.md
├── {aspect}/
│   ├── spec.md
│   ├── plan_YYYYMMDD.md
│   └── ...
└── ...
```

### PRD structure

- **Problem Statement**, **Goals & Success Metrics**, **User Personas & Scenarios** (Pry ICP:
  solo/indie builders and teams who want proof an app they own is safe before launch),
  **Requirements** (must/should/nice), **Technical Considerations** (name the `P`-capability, the
  ownership-gate and intensity-level impact), **Risks & Open Questions** (reference `R1`..`R7`,
  with special attention to legal/ethical risk), **Out of Scope**.

Include when relevant: Ownership-Proof Schema, Probe/Finding Schema, Proof-Bundle Contract,
Non-Functional Requirements.

After writing, surface open questions. Offer to continue into aspect decomposition.

## Aspect Decomposition Mode

1. Propose aspect candidates, each with a one-line boundary.
2. Confirm aspect names (`kebab-case`).
3. Write or update `docs/planning/{slug}/{aspect}/spec.md`.

Each `spec.md`: problem slice, in-scope requirements, out-of-scope boundaries, acceptance
criteria (testable), dependencies/sequencing, open questions/risks.

## Edge Cases

- **Update existing PRD**: Read, ask what changed, update in place.
- **User says "just write it"**: Write from what you have, flag gaps, include one challenge question.
- **No brief exists**: Run full discovery from conversation.
- **Greenfield with no code to read**: Ground in the roadmap/design docs; say plainly no implementation exists yet.
