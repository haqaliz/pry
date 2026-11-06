# Aspect Spec — Local Sandbox Intake

- **Feature:** `target-intake-real`
- **Aspect:** `local-sandbox`
- **PRD:** `../prd.md`
- **Status:** Implemented and merged (2026-11-07)

## Problem slice

P2 needs one trustworthy operation: take a local repository, boot it in Docker without
giving it the host, and write a pinned snapshot of what ran. This aspect covers local
repos only; live URLs are deferred.

## In scope

- Path validation and a temp copy of the working tree (never the original).
- Project detection: static `index.html`, npm-based Node with a `start`/`dev` script.
- Docker build phase (network allowed) and run phase (`--network=none`).
- Readiness via `docker exec`, not a published host port.
- Snapshot JSON plus capped build/run logs in a durable run directory.
- Cleanup on success, failure, timeout, and SIGINT; `--keep` opt-out.
- CLI `pry intake PATH` with `--json`, `--out`, `--keep`, `--port`, `--timeout`.
- Named failure causes and offline unit tests; opt-in Docker integration tests.

## Out of scope

- Live URL intake, P1 token plumbing for URLs.
- Probes, findings, proof bundles, verdicts.
- Python/FastAPI, yarn/pnpm/Bun, Windows, remote sandboxes.
- Host port publishing and host networking.
- Docker socket mounts, privileged mode, host PID/IPC/UTS, devices.

## Acceptance criteria

PRD AT1–AT16. Every AT maps to a test in the plan.

## Dependencies and sequencing

- Depends on merged P1 (`master` at `6879ea8` or later).
- No new Python dependencies. Docker CLI is an external requirement.
- Python 3.9.6: no `X | Y`, no `match`, no `tomllib`.
- Default test suite is offline; Docker tests require `PRY_DOCKER_TESTS=1`.

## Open questions

None blocking. Build network is allowed by default; `--offline-build` is a should-have.
Run readiness uses `docker exec`; P3 will reuse that transport or add a sidecar.
