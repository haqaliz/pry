# Pry Ethics and Responsible Disclosure

- **Status:** Approved (2026-11-07). Re-review before any public finding or change to the
  probe suite or intensity levels.
- **Owner:** aliz
- **Last updated:** 2026-11-07

## What Pry asserts

- **EXPOSED** means Pry reproduced the issue and saved the request/response pair that
  demonstrates it, at or below the authorized intensity.
- **NOT_REPRODUCED** means the issue could not be confirmed. It is not proof that the app is
  safe.
- **UNVERIFIED** means the check could not run: ownership unproven, target unreachable, or the
  authorized intensity too low.
- There is no **SAFE** or **SECURE** verdict. Pry never claims an app is secure.

## Ownership and authorization

- Pry only runs against a target the user has proven they control, at every intensity level,
  including the lowest.
- A local repository is different: the user already has the files. Local intake does not need
  a P1 token. Any target reached over the network still does.
- Do not use Pry on a shared host, a customer environment, or a third-party service unless the
  user has written authorization from the owner.
- Do not resell access to Pry's findings or use them against anyone but the app's owner.

## Data minimization

- Capture only the minimum request and response needed to demonstrate the finding.
- Redact secrets, personal data, and anything beyond the proof. Prefer showing the key name or
  the fact of exposure over the value itself.
- Never exfiltrate more data than the proof needs. No bulk downloads, no dumping a database, no
  reading other users' records.
- Proof stays local unless the owner explicitly chooses to share it. No upload, telemetry, or
  third-party service by default.

## Intensity and destructive actions

- Level 0 is read-only and always on: GET/HEAD-style checks only.
- Level 1 is expanded read-only work and requires explicit per-target confirmation.
- Local Level 1 SSRF requires `--confirm`; the callback sidecar has no egress. A callback hit
  proves the app fetched an internal URL, not arbitrary external egress. No live SSRF.
- The rate-limit observation is a bounded sample and a hardening observation, not a verdict.
  Local: 1–20 GETs. Live: max 5 GETs, 0.5s apart, level 1 + `--confirm`, stop on the first
  429/503/`Retry-After`. A missing limit is not `EXPOSED`. Live sampling can still cause load
  or a lockout; do not point it at login or account-recovery paths on a shared target.
- The opt-in header observation is one GET to `/` on a local or live scan. Missing or present
  recommended headers are a hardening observation, not a verdict or proof. A CDN or proxy may
  set them, so the result quotes the response and claims nothing global.
- The served-database check is four fixed GETs for conventional database paths. A SQLite
  header or SQL-dump signature is `EXPOSED`, but only a short signature excerpt is stored;
  rows and binary content are never kept. A clean result says nothing about other paths.
- Level 2 is write-based confirmation. It runs only against a sandbox or staging copy by
  default. Against a live target it needs an additional explicit confirmation beyond the
  standard warning.
- Stop immediately if a check appears to touch shared data, trigger a real notification, or
  alter state. Report it as UNVERIFIED rather than continuing.

## Live read-only scans

- Require a P1 token for the target origin; validate it before any request.
- GET only; no `Authorization`/`Cookie`; no writes; up to 12 requests, plus one for
  `--headers`, one per `--endpoint`, three for configured IDOR, and up to five for a live
  rate-limit observation.
- Not a load test: live SSRF, Level 2, and write-based checks are not implemented. Local Level
  1 SSRF and the bounded local/live rate-limit observations are separate and require
  `--confirm`; the live rate-limit sample is capped at five GETs and stops on the first
  throttle.
- The P1 token is the owner's authorization. If the target is shared or production, the owner
  must confirm they control it.
- Configured live and local IDOR credentials come from a 0600 file, are used only for the three
  requests, and are redacted from stored results, proofs, reports, logs, and errors. The local
  config is mounted read-only into the sandbox and removed afterward. No discovery in this
  slice; the config declares the object pair.

## Responsible disclosure

- If a finding affects real user data or a third party, stop and notify the app owner.
- The app owner decides whether and when to disclose. Pry does not publish a finding, case
  study, or screenshot without the owner's written consent.
- Default disclosure window: 90 days from the owner's acknowledgment, or sooner by mutual
  agreement. Critical findings may justify a shorter window; the owner and the affected users
  come first.
- Security contact: `security@example.invalid` (placeholder; the owner must replace this with a
  monitored address before any public release).
- Do not include customer names, live secrets, or personal data in a public write-up.

## Prohibited use

- Scanning a target you do not own or have written permission to test.
- Denial of service, destructive writes, persistence, lateral movement, or data exfiltration
  beyond the minimum proof.
- Using Pry to harass, extort, or gain unauthorized access.
- Selling findings, access, or target data.

## Limitations to state plainly

- Docker is not a kernel-level security boundary. It contains accidents and ordinary build
  scripts, not a determined kernel attacker.
- Build phases may run third-party dependency code with network access.
- DNS TXT ownership without DNSSEC is spoofable; the well-known HTTPS method is stronger.
- A clean result is not a security guarantee. Absence of a reproduced finding is not proof of
  absence.

## Changes

This file must be reviewed whenever the probe suite, intensity levels, or disclosure process
changes. P3 must not land before this draft is approved.
