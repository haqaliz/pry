# Pry: Capability Roadmap

Engine capabilities in build order. Each lands test-first. P1 ownership gate implemented;
P2 local intake implemented; P3 read-only probe slice implemented (including declared
unauthenticated endpoints); P5 read-only signed bundles implemented for local findings; live
URL, P4, and the rest of P5 onward are not.

| ID | Capability | Depends on | Guardrail tie-in |
|---|---|---|---|
| **P1** | **Ownership verification.** DNS TXT or well-known-file proof that the user controls the target (account linking deferred). Gates every level, including read-only. | none | Constraint 1 |
| **P2** | **Target intake.** Local repo booted in an isolated Docker sandbox (static + npm Node/Next first); records a pinned snapshot. Live URL intake deferred. | P1 | Sandbox before live |
| **P3** | **Floor probe suite (read-only, always on).** First slice: CORS with credentials, verbose error leakage, exposed secret files, declared unauthenticated endpoints. Endpoint discovery, IDOR/access control, exposed DB/open rules, and header-only findings deferred. | P1, P2 | Constraint 2, read-only default |
| **P4** | **Intensity-gated probe suite.** Level 1: non-mutating SSRF probes, rate-limit probing. Level 2: write-based confirmation, sandbox/staging only by default, extra confirmation for a live target. | P3 | Constraints 2 and 6 |
| **P5** | **Exploit proof capture and verdict.** `EXPOSED` / `NOT_REPRODUCED` / `UNVERIFIED`, each backed by a signed, redacted request/response record. Read-only local slice implemented with Ed25519 bundles; live replay and P4 integration deferred. | P3, P4 | Constraints 3, 4, 5 — the moat |
| **P6** | **Findings corpus and report.** Bank (target, probe, verdict, proof); generate a shareable report for the app owner. | P5 | Measured, not guessed |
| **P7** | **Platform integration (deferred).** Pre-publish check pluggable into Lovable/Replit/Base44-style platforms. | P3-P6 | Needs partnerships; not scheduled |

## Sequencing

P1 is hardened before any other code runs against a real target — not merely built first, but
gating everything downstream. P2 local intake and the P3 read-only probe slice (including
declared unauthenticated endpoints) are implemented; live URL intake and the remaining P3
checks follow, then P4 widens coverage behind explicit consent.
P5 is the moat. P6 makes results publishable and reportable. P7 is business development, deferred.

## Open questions

- Account linking (OAuth) is deferred; DNS TXT and well-known file ship at launch.
- Exact boundary between Level 1 and Level 2 for probes that are "mostly" read-only (e.g. a
  rate-limit probe that sends many requests).
