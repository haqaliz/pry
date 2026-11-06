# Target Intake, For Real (P2)

- **Type:** feat
- **Slug:** `target-intake-real`
- **Owner:** aliz
- **Source:** inline brief. No GitHub issue for this slug; this file is the brief.
- **Capability:** P2 — target intake. Depends on P1, which is merged.

## Brief

Boot a local repository in an isolated sandbox and record a pinned snapshot of exactly
what was tested. This is the first half of P2; live-URL intake is a separate slice.
The sandbox must be real: a copy of the repo, a container with no host socket, no host
filesystem mount, resource limits, a build phase that may use the network, and a run
phase with no outbound network. The output is a snapshot that P3 can attribute every
finding to.

## Current state

- `master` has P1 only. There is no `src/pry/intake/` directory.
- The old `feat-target-intake-aliz` commit `0f51bc5` is a mock: it creates a temp
  directory and writes a placeholder `snapshot.json`; it does not boot, isolate, or
  inspect anything. It is not a dependency and must not be merged.
- Docker 29.9.2 is installed and the daemon is running. Node 22 is available on the host
  for fixture creation, but the sandbox must not depend on host Node.

## Scope (provisional, confirm in interview)

1. Local repo intake only. Live URL intake is deferred.
2. Docker-backed sandbox runner; no host socket, no privileged mode.
3. Supported target slice: static sites and Node/Next apps (confirm).
4. Detect the app type and start command; build with network allowed; run with no egress.
5. Readiness check inside the sandbox; record the reachable internal URL.
6. Pinned snapshot JSON: original path, git commit, dirty state, file hashes, lockfile
   hash, base image digest, runtime versions, build command, start command, port,
   timestamps, and sandbox id.
7. Cleanup on success, failure, timeout, and interrupt. Never leave a container running.
8. Clear failure causes: `REPO_NOT_FOUND`, `UNSUPPORTED_PROJECT`, `BUILD_FAILED`,
   `START_FAILED`, `READY_TIMEOUT`, `SANDBOX_ERROR`, `DOCKER_UNAVAILABLE`.

## Out of scope

- Floor probes, exploit reproduction, or any verdict.
- Live URL intake and ownership-token plumbing for URLs.
- Python/Flask/Django intake (defer unless the interview says otherwise).
- Write-based checks, hosted sandboxing, GPU, Windows.
- Modifying the source repo. The sandbox works on a copy.

## Acceptance criteria (draft)

- A fixture static site boots in the sandbox and answers a readiness request.
- A fixture Node app installs, builds, and boots, then answers a readiness request.
- The run phase has no outbound network; a fixture that tries to reach the internet
  fails.
- The host repo is unchanged after intake (same git status and file hashes).
- A build or start failure returns the named cause and leaves no container.
- The snapshot records the commit, dirty state, lockfile hash, image digest, start
  command, port, and timestamps.
- Docker unavailable → `DOCKER_UNAVAILABLE`, no partial sandbox.
- Tests are offline: Docker is faked at the runner boundary; one opt-in integration test
  uses Docker and small local fixtures, never a third-party target.

## Notes

- Local repo intake does not need a P1 token: the user already has the files. Any target
  reached over the network still requires P1.
- `ETHICS.md` is still missing and must land before P3, not before P2.
- Base branch `master`; branch `feat/target-intake-real/aliz`.
