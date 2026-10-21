# Pry: Project Context for Claude Code

This file orients a coding agent working in this repository. Read it first. Deeper context
lives in the `docs/` folder.

---

## What this project is

**Pry** proves that an app you own is exposed, by actually trying the exploit against it, never
by pattern-matching for "looks risky." Point Pry at a target you've proven you own — a live URL
or a local repo booted in a sandbox — and it runs a graduated set of checks, read-only by
default, and reports only what it could reproduce: the exact request, the exact response, the
data it should not have returned.

The name: to *pry* something open is to force it, physically, to see whether it holds. Pry asks
of an app: *does it actually hold, or does it give?*

Status: **day zero.** Nothing is built. This file, `VISION.md`, and `docs/` are all that exist.
Do not describe capability that isn't there yet.

Lineage: one of three siblings scaffolded together on 2026-10-22 (with Assay and Tenon) from a
market-demand pass (`~/dev/at/ideas/market-demand-2026-10.md`), prompted by the scale of exposed
vibe-coded apps (Red Access: ~5,000 corporate apps found on Lovable/Replit/Base44, 40% with
sensitive data and no basic controls). Standalone: no code dependency on sibling projects.

---

## The wedge (read this before proposing any feature)

- **Pattern-matching for likely vulnerabilities.** What most scanners do: "this endpoint has no
  visible auth check" from reading code or responses. High false-positive rate, and it cannot
  tell a real exposure from a false alarm. **We do NOT build this as the verdict.**
- **Reproducing the exploit and capturing the proof.** Actually make the request that should have
  been blocked; capture what came back. **This IS the product.** `EXPOSED` means Pry has a saved,
  replayable request/response pair that demonstrates the issue — not an inference.

---

## Key strategic constraints (do not violate)

1. **Ownership is proven before anything runs, at every intensity level, including the lowest.**
   No scan of a target the user has not proven they control. See `docs/technical/ARCHITECTURE.md`
   for the verification mechanism (DNS TXT / well-known file / account-linking).
2. **Read-only by default. Higher intensity requires explicit, per-target confirmation.** The user
   selects an intensity level before each run; the floor (always-on, read-only checks) cannot be
   disabled, and anything beyond read-only requires an explicit warning and confirmation,
   especially against a live/production target.
3. **Never claim "secure."** Pry's verdict space has no "safe" state. Absence of a reproduced
   finding is `NOT_REPRODUCED`, never "this app is secure." Over-claiming here causes real harm.
4. **Execution decides, never a guess.** A static heuristic may prioritize what to try. Only a
   reproduced request/response pair may produce `EXPOSED`.
5. **Minimize data touched.** A proof captures only what is necessary to demonstrate the finding;
   redact anything beyond that, and never exfiltrate more than the minimum needed to show the
   point.
6. **No destructive action without an explicit sandboxed target.** Writes that could alter or
   delete real data require a sandbox/staging copy, not a live target, except where the user has
   explicitly raised the intensity level with full warning on a target they own.
7. **Responsible disclosure and an ETHICS.md before any public finding or case study.**
8. **Test-first.** Every capability lands with its failing test written first.

---

## Verdict contract

| Verdict | Meaning | May be emitted when |
|---|---|---|
| **EXPOSED** | A real exploit was reproduced | Pry captured a request/response pair demonstrating the issue, at or below the authorized intensity |
| **NOT_REPRODUCED** | The suspected issue could not be confirmed | Absence of proof is not proof of absence; never rendered as "safe" |
| **UNVERIFIED** | Could not test | Ownership unproven, target unreachable, or the authorized intensity was too low to test this class |

No "SAFE" or "SECURE" verdict exists. A heuristic may prioritize; a reproduced exploit decides.

---

## Intensity levels (draft, confirm in planning)

- **Level 0 (default):** read-only, floor checks only (missing auth, broken access control,
  exposed secrets, exposed database/open rules, verbose errors, missing headers/open CORS).
- **Level 1:** read-only, expanded checks (non-mutating SSRF probes, rate-limit probing).
- **Level 2:** write-based confirmation, sandbox/staging target only by default; against a live
  target requires an additional explicit confirmation step beyond the standard warning.

---

## Tech direction

- **Python core** (via `uv`), CLI-first (`pry`), self-hostable OSS; monetization experiment is a
  crypto-based subscription for a hosted tier, falling back to OSS-plus-donation (Plumb's model)
  if that proves unworkable. Details in `docs/technical/ARCHITECTURE.md`.
- Target intake: local repo booted in a sandbox (safest, build first), then a live URL with proof
  of ownership.
- Every `EXPOSED` finding ships as a replayable, signed proof bundle.

---

## Founder profile

Solo / small team. Full-stack developer + ML engineer. The moat is engineering
(exploit-reproduction plus proof), not a vulnerability database.

---

## Folder / docs structure

```
README.md
VISION.md
CLAUDE.md                          # This file
LICENSE                            # Apache-2.0
docs/
  ROADMAP.md                       # Phases + risk register
  technical/CAPABILITY_ROADMAP.md  # P1..P7 capabilities in build order
  technical/ARCHITECTURE.md        # own -> intake -> probe -> prove -> report
  planning/{slug}/                 # In-flight PRDs, specs, plans
```

---

## Quick facts for grounding (do not fabricate beyond these)

- Red Access scanned 380,000+ web assets on Lovable, Replit and Base44; found ~5,000 built for
  corporate purposes; 40% of those (~2,000) held sensitive data with no basic security controls;
  ~2,000 had no authentication at all.
- Escape.tech scanned 1,400+ production vibe-coded apps: 65% had security issues, 58% at least
  one critical, 400+ exposed secrets.
- Lovable (June 2026): 80% of its builders identify as non-technical.
- A separate Q1 2026 assessment of 200+ apps found 91.5% had at least one vulnerability traceable
  to AI hallucination.
- 61% of IT leaders cite ungoverned AI usage as their top security barrier (cited survey).

If you need a statistic that isn't here, say it's unverified.
