# Pry: Roadmap

Goal: **reputation and moat** in about 3 months, in parallel with Assay and Tenon. Form: OSS CLI
core first; a crypto-subscription hosted tier is an explicit experiment, with OSS-plus-donation
as the fallback. Stack: Python via `uv`.

Milestone order is my proposal; reorder freely.

---

## Phase 0: Ownership and ethics before anything runs (weeks 1-3)

**Gate: ownership verification works, and no probe code exists yet without it.**

| # | Milestone | Done when |
|---|---|---|
| M0.1 | Ownership verification (P1) | DNS TXT and well-known-file methods both work; a target without proof cannot be scanned at any level |
| M0.2 | ETHICS.md and ToS draft | What `EXPOSED` does and does not assert; responsible-disclosure process; written before P3 lands |
| M0.3 | Local sandbox target intake (P2) | A local repo boots in an isolated sandbox for testing; no live target touched yet |

## Phase 1: OSS core, read-only (weeks 4-8)

| # | Milestone | Done when |
|---|---|---|
| M1.1 | Floor probe suite (P3) | Missing auth, broken access control, exposed secrets, exposed DB/open rules, verbose errors, header/CORS checks — all read-only |
| M1.2 | Proof capture (P5, read-only slice) | Every `EXPOSED` carries a saved, redacted request/response pair |
| M1.3 | `pry scan <target>` CLI | Level 0 only; exit code reflects verdict; JSON output byte-stable |
| M1.4 | First real finding on an app you own | Published as a case study, with ETHICS.md's disclosure process followed |

## Phase 2: Intensity levels and live targets (weeks 8-12)

| # | Milestone | Done when |
|---|---|---|
| M2.1 | Live-target ownership flow | DNS/file verification works against a real domain, not just local fixtures |
| M2.2 | Level 1 expanded read-only checks (P4) | Non-mutating SSRF probes, rate-limit probing, with per-level confirmation |
| M2.3 | Level 2 write-based confirmation (P4) | Sandbox/staging only by default; live target requires an extra explicit step |
| M2.4 | Findings corpus and report (P6) | Bank (target, probe, verdict, proof); shareable report for the app owner |

## Phase 3: Monetization experiment and platform integration (after the window)

Crypto-subscription hosted tier as a trial; fallback to OSS-plus-donation if it doesn't work.
Pre-publish check for Lovable/Replit/Base44-style platforms (needs partnerships, not scheduled).

---

## Risk register

| ID | Risk | L/I | Mitigation |
|---|---|---|---|
| R1 | Ownership-proof bypass lets someone scan a target they don't control | Low/Critical | Hardened first, before any probe code; multiple verification methods |
| R2 | A "read-only" probe causes a side effect (lockout, cache invalidation) | Med/High | Document exactly what each floor probe does; conservative defaults |
| R3 | False `EXPOSED` | Low/High | Require a captured request/response; no finding without reproducible proof |
| R4 | Legal exposure even with ownership proof (other users' data touched) | Med/High | ETHICS.md and ToS before Phase 1 ships; minimize data touched |
| R5 | Crypto-subscription model does not work | Med/Med | Treat as an experiment; OSS-plus-donation is the explicit fallback |
| R6 | Scope creep across vulnerability classes | High/Med | Floor first, intensity levels gate the rest |
| R7 | Platform-partnership dependency for pre-publish integration | Med/Low | Not scheduled in the 3-month window |
