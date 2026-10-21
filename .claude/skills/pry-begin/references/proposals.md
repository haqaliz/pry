# Phase A — Diagrams & proposal PDFs

## 1. Diagrams (`excalidraw`)

Typical set for Pry:

| Diagram | When to include |
|---|---|
| System / architecture | Almost always — own → intake → probe → prove → report |
| Data flow | A target moves through ownership verification, intake, and probing |
| Sequence | The ownership-verification flow, or a probe-and-capture sequence |
| State machine | A verdict transition (`EXPOSED`/`NOT_REPRODUCED`/`UNVERIFIED`), or an intensity-level escalation with its confirmation step |

**Every text element must set `fontFamily: 2` (Helvetica).**

**Diagram the ownership gate and the verdict honestly.** Every diagram that shows
a probe running must show it after the ownership-verification step, never
before, at any intensity. Never draw a "secure" or "safe" state — only
`EXPOSED` / `NOT_REPRODUCED` / `UNVERIFIED` exist.

## 2. Export to SVG (`excalidraw-to-svg`)

## 3. Write the two proposals

### `<type>-<id>-technical-proposal.md`

Summary, current state, proposed design, data/interface changes (ownership-proof
schema, probe/finding schema, proof-bundle contract), risks/trade-offs
(especially legal/ethical ones), effort/sequencing (reference the
`P`-capability), open questions.

### `<type>-<id>-non-technical-proposal.md`

The problem in plain language, what we'll do, why it matters (an app owner who
wants proof their app is safe before launch), what changes for users, timeline,
risks. Never imply the app is "secure" — say what was and wasn't reproduced.

## 4. Convert to PDF (`md-to-pdf`)

```bash
cd docs/planning/{slug}/proposals
PUPPETEER_EXECUTABLE_PATH="/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" \
  md-to-pdf <type>-<id>-technical-proposal.md --basedir ..
PUPPETEER_EXECUTABLE_PATH="/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" \
  md-to-pdf <type>-<id>-non-technical-proposal.md --basedir ..
```

Verify: `pdftoppm -png -r 70 -f 1 -l 1 <type>-<id>-technical-proposal.pdf /tmp/check`

## 5. Approval gate

Present both PDFs and stop.
