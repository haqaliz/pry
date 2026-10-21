# Pry: Capability Roadmap

Engine capabilities in build order. Each lands test-first. Nothing is built yet.

| ID | Capability | Depends on | Guardrail tie-in |
|---|---|---|---|
| **P1** | **Ownership verification.** DNS TXT, well-known file, or account-linking proof that the user controls the target. Gates every level, including read-only. | none | Constraint 1 |
| **P2** | **Target intake.** Local repo booted in an isolated sandbox (build first); a live URL once P1 covers it. Records a pinned snapshot of what was tested. | P1 | Sandbox before live |
| **P3** | **Floor probe suite (read-only, always on).** Missing authentication, broken access control/IDOR, exposed secrets, exposed database/open rules, verbose error leakage, missing security headers/open CORS. | P1, P2 | Constraint 2, read-only default |
| **P4** | **Intensity-gated probe suite.** Level 1: non-mutating SSRF probes, rate-limit probing. Level 2: write-based confirmation, sandbox/staging only by default, extra confirmation for a live target. | P3 | Constraints 2 and 6 |
| **P5** | **Exploit proof capture and verdict.** `EXPOSED` / `NOT_REPRODUCED` / `UNVERIFIED`, each backed by a signed, redacted request/response record. | P3, P4 | Constraints 3, 4, 5 — the moat |
| **P6** | **Findings corpus and report.** Bank (target, probe, verdict, proof); generate a shareable report for the app owner. | P5 | Measured, not guessed |
| **P7** | **Platform integration (deferred).** Pre-publish check pluggable into Lovable/Replit/Base44-style platforms. | P3-P6 | Needs partnerships; not scheduled |

## Sequencing

P1 is hardened before any other code runs against a real target — not merely built first, but
gating everything downstream. P2 and P3 follow, then P4 widens coverage behind explicit consent.
P5 is the moat. P6 makes results publishable and reportable. P7 is business development, deferred.

## Open questions

- Which ownership-verification methods to support at launch (DNS TXT and well-known file are the
  two cheapest to build; account-linking needs OAuth plumbing).
- Exact boundary between Level 1 and Level 2 for probes that are "mostly" read-only (e.g. a
  rate-limit probe that sends many requests).
