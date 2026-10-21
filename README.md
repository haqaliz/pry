# Pry

**Proves an app you own is exposed, by actually trying the exploit.** Read-only by default;
reports only what it could reproduce.

[![Status](https://img.shields.io/badge/status-day%20zero%20·%20design%20only-lightgrey)](docs/ROADMAP.md)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)

[Vision](VISION.md) · [Roadmap](docs/ROADMAP.md) · [Architecture](docs/technical/ARCHITECTURE.md) · [Capabilities](docs/technical/CAPABILITY_ROADMAP.md)

---

## Status

**Nothing is built yet.** This repository holds design docs only. Read `CLAUDE.md` before writing
any code here, especially the ownership-gate and verdict-contract sections.

## What Pry is

Point Pry at a target you've proven you own — a local repo booted in a sandbox first, a live URL
with ownership verification later. It runs a graduated set of checks and reports only what it
reproduced: the exact request and response.

## What Pry is not

- Not a pattern scanner. It does not report "this looks risky" — only what it actually broke.
- Not a claim of "secure." There is no safe verdict.
- Not a tool for scanning anyone's app but your own, proven, target.

## The verdict

| Verdict | Meaning |
|---|---|
| `EXPOSED` | A real exploit was reproduced, with saved request/response proof |
| `NOT_REPRODUCED` | Could not confirm the suspected issue (not a claim of safety) |
| `UNVERIFIED` | Could not test (ownership unproven, unreachable, or intensity too low) |

## Intensity levels

Read-only floor checks by default (missing auth, broken access control, exposed secrets, exposed
database/open rules, verbose errors, missing headers). Higher levels, up to write-based
confirmation on a sandbox/staging copy, require explicit per-target confirmation and warning.

## Docs

- [`VISION.md`](VISION.md)
- [`CLAUDE.md`](CLAUDE.md)
- [`docs/ROADMAP.md`](docs/ROADMAP.md)
- [`docs/technical/CAPABILITY_ROADMAP.md`](docs/technical/CAPABILITY_ROADMAP.md)
- [`docs/technical/ARCHITECTURE.md`](docs/technical/ARCHITECTURE.md)

## Lineage

One of three siblings scaffolded on 2026-10-22 with [Assay](../assay) and [Tenon](../tenon),
sharing house DNA with [Belay](../belay) and [Plumb](../plumb). Standalone by design.
