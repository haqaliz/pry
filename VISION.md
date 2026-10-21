# Pry: Vision

> A scanner that guesses is an opinion. A scanner that tried is a proof.

---

## The bet in one sentence

Vulnerability scanners mostly guess from patterns and drown their users in false positives. Pry
wins by **reproducing the exploit against an app you own and showing the exact proof** — the
request, the response, the data it should not have returned — read-only by default, and nothing
stronger without your explicit say.

---

## Why now

- **Vibe-coded apps shipped faster than anyone secured them.** Red Access found ~5,000 corporate
  apps on Lovable/Replit/Base44, 40% holding sensitive data with no basic controls, ~2,000 with
  no authentication at all.
- **The flaws are common and mechanical.** Escape.tech found 65% of 1,400 production vibe-coded
  apps had an issue, 58% a critical one. 80% of Lovable's builders are non-technical, so the
  default posture is "it's just for our team" becoming a public URL.
- **Trust in scanner output is low.** High false-positive rates push teams to ignore scanner
  findings. A reproduced exploit is harder to dismiss than a heuristic flag.

---

## The founder's unfair advantage

Reproducing an exploit and capturing clean proof is an execution problem, the same discipline
behind Plumb and Belay: do the thing, capture what happened, report honestly. No vulnerability
database or security-vendor relationship is required to start on the handful of mechanical,
well-understood flaw classes named in `CLAUDE.md`.

---

## Why it's defensible

The durable core is the ownership-verification gate, the graduated probe suite, and the proof
capture and replay. A stronger model proposes better probe sequences and interprets responses
more precisely; the reproduced request/response pair is still the thing that decides, so a
better model sharpens coverage without replacing the proof discipline.

---

## Positioning

- **Not a pattern scanner.** Existing tools (Snyk, Escape) flag likely issues from source or
  traffic. Pry's wedge is trying the thing and keeping the proof.
- **Never claims "secure."** There is no safe verdict. `NOT_REPRODUCED` is the honest ceiling.
- **Ownership-gated.** Pry never scans a target the user has not proven they control, at any
  intensity, including read-only.

---

## The wedge to the company

1. **OSS on-ramp:** a CLI that boots a local repo in a sandbox and runs the read-only floor
   checks, with signed proof output. Free, self-hostable.
2. **Live-target mode:** add ownership-verified live URL scanning with graduated intensity.
3. **Monetization experiment:** a crypto-based subscription for a hosted tier (batch scanning,
   report hosting, continuous checks). If that does not prove viable, fall back to OSS-plus-
   donation, the same pattern as Plumb — no pivot to selling user data or lowering the
   ownership/consent bar to reach revenue.

---

## Non-goals

- Scanning any target without proven ownership, at any intensity.
- Claiming an app is "secure" or "safe."
- Destructive testing against a live target without explicit, per-target, per-level confirmation.
- Selling findings or access to anyone but the app's own owner.

---

## The one-line mantra

**Try it for real. Keep the proof. Never claim more than what broke.**
