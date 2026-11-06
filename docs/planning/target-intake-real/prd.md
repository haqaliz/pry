# PRD — Target Intake, For Real (P2)

- **Status:** Draft, awaiting review gate
- **Owner:** aliz
- **Date:** 2026-11-07
- **Slug:** `target-intake-real`
- **Capability:** P2 (depends on the merged P1 gate)
- **Branch:** `feat/target-intake-real/aliz`

## Problem Statement

P1 proves the user controls a target. P2 must produce something safe to test: a local
repository booted in an isolated sandbox, with a pinned record of exactly what was
started. Today there is no intake code at all. The old `0f51bc5` attempt creates a temp
directory and writes a placeholder snapshot; it never boots anything.

Without P2, P3 has no target. Without isolation, P3 would run exploit logic against a
build script and an app that share the host. The sandbox is the boundary that lets Pry
run untrusted repository code without giving it the user's filesystem, network, or
Docker socket.

**If we do not build this:** P3 cannot start, and any attempt to run probes against a
local repo would execute that repo's build scripts directly on the host.

**What we are choosing not to build:** live-URL intake, Python/FastAPI intake, yarn/pnpm
support, probes, proof capture, remote or hosted sandboxes.

**Six-month failure scenario:** the sandbox works on the happy path but a build script
hangs, fills the disk, or leaves a container running; the snapshot is not reproducible;
users stop trusting the tool. Mitigations: hard timeouts, resource limits, guaranteed
cleanup, and a snapshot that records the image digest and tree hash.

## Goals & Success Metrics

1. **Boot a local repo in a real Docker sandbox.** No host socket, no host repo mount,
   no host network during the run phase, non-root run user, capability drop, resource
   limits, and a hard timeout.
2. **Record a pinned snapshot.** Original path, git commit, dirty state, tree hash,
   package manager, lockfile hash, base image digest, build/start commands, port,
   timestamps, and container id.
3. **Clean up every time.** Success, build failure, start failure, timeout, SIGINT, and
   unexpected exceptions all remove the container and the temp copy.
4. **Fail with named causes.** No traceback, no orphan container, no partial sandbox.
5. **Keep the default suite offline.** Docker is faked at the runner boundary; a small
   opt-in integration suite uses local fixtures only.

Success metrics:

- A static fixture and a Node fixture both reach ready state.
- A fixture that attempts outbound network access during the run phase fails.
- The host repository is byte-for-byte unchanged after intake.
- A failed build leaves no container and no temp copy.
- Every failure path returns its named cause.
- The default `uv run pytest` suite makes zero Docker calls.

## User Personas & Scenarios

**App owner.** Has a local checkout of an app. Runs `pry intake ./app`, gets a snapshot
and a sandbox that P3 can probe. They do not need a P1 token: they already have the
files. Any target reached over the network still needs P1.

**Maintainer.** Builds P3. Calls the intake API, receives a `Sandbox` object and a
snapshot, and runs probes against the internal URL while the container has no egress.

**Scenario:**

```bash
pry intake ./my-next-app
# -> boots the repo in a Docker sandbox
# -> writes ~/.pry/runs/<id>/snapshot.json (plus capped logs)
# -> prints the snapshot path and the sandbox summary
# -> removes the container and temp copy
```

## Requirements

### Must-have

| ID | Requirement |
|---|---|
| M1 | **Path validation.** Resolve the path; require an existing directory. Reject missing paths with `REPO_NOT_FOUND`. Do not follow a symlink outside the given path without recording the resolved path. |
| M2 | **Temp copy.** Copy the working tree (including uncommitted changes) to a temp directory, excluding `.git`, `node_modules`, `.venv`, `dist`, `build`, `.next`, and other generated trees. Record the original git commit and dirty state before copying. Never mount the original repo into a container. |
| M3 | **Project detection.** Static: `index.html` at the root and no usable start script. Node/Next: `package.json` with a `scripts.start` or `scripts.dev` entry. npm only in this slice; yarn/pnpm → `UNSUPPORTED_PROJECT` with a clear message. |
| M4 | **Build phase.** Docker, network allowed, only the temp copy mounted. `npm ci` when `package-lock.json` exists, else `npm install --no-audit --no-fund`. Run `npm run build` when the script exists. Hard timeout and log cap. Nonzero exit → `BUILD_FAILED`. |
| M5 | **Run phase.** Docker with `--network=none`, non-root user, read-only root filesystem, `--cap-drop=ALL`, `--security-opt=no-new-privileges`, memory/CPU/PID limits, and a hard readiness timeout. Start command: `npm run start`, else `npm run dev`; static uses `python -m http.server` in a slim Python image. |
| M6 | **Readiness.** Poll inside the container (no host port publishing) until the app answers on `127.0.0.1:<port>`. Default port 3000 for Node, 8000 for static; `--port` overrides. Failure → `READY_TIMEOUT`. |
| M7 | **Pinned snapshot.** JSON, versioned, written atomically to `~/.pry/runs/<id>/snapshot.json` (or `--out`): target path, kind, git commit, dirty flag, tree hash, package manager, lockfile hash, image, image digest, build/start commands, port, sandbox id, container id, network mode, limits, timestamps, and result status. Logs are capped at 1 MiB each and stored beside the snapshot with 0600 permissions. |
| M8 | **Cleanup.** `try/finally` plus SIGINT handling: remove the container and temp copy on every path. `--keep` is the explicit opt-out for debugging; it prints the container id and the cleanup command. |
| M9 | **Named failures.** `REPO_NOT_FOUND`, `UNSUPPORTED_PROJECT`, `DOCKER_UNAVAILABLE`, `COPY_FAILED`, `BUILD_FAILED`, `START_FAILED`, `READY_TIMEOUT`, `SANDBOX_ERROR`, `SNAPSHOT_FAILED`, `INTERRUPTED`. |
| M10 | **CLI.** `pry intake PATH [--json] [--out DIR] [--keep] [--port PORT] [--timeout SECONDS]`. Success exits 0. Intake failure prints `UNVERIFIED: <CAUSE>: <message>` and exits 1. Usage errors exit 2. No P1 token for a local path. |
| M11 | **Tests.** Offline unit tests with a fake runner; snapshot schema and hash tests; cleanup-on-failure tests; security-flag assertions. An opt-in Docker integration suite (`PRY_DOCKER_TESTS=1`) with static and Node fixtures, including an egress-blocked fixture. |
| M12 | **Docs.** README status and usage; architecture update that P2 is implemented (local repo only, live URL deferred); roadmap status. No claim that live URL or probes work. |

### Should-have

| ID | Requirement |
|---|---|
| S1 | Detect `next.config.*` and prefer `npm run build` + `npm run start` for Next. |
| S2 | `--offline-build` for repos whose dependencies are vendored; build with `--network=none`. |
| S3 | A `--timeout` that applies separately to build and readiness, with sensible defaults (10 min build, 60 s ready). |
| S4 | A machine-readable `--json` result that includes the snapshot object, not just a path. |

### Nice-to-have (not this change)

yarn/pnpm, Python/FastAPI, live URL intake, remote sandbox backends, custom seccomp
profiles, Windows, rootless Docker.

## Technical Considerations

**Pipeline fit.** P2 sits between P1 and P3. Local intake does not consume an ownership
token because the user already has the files; any URL path still requires P1. The
sandbox exposes an internal `http://127.0.0.1:<port>` to P3 while the container has no
egress.

**Docker image choice.**

- Node/Next: `node:22-bookworm-slim`.
- Static: `python:3.9-slim`, serving with `python -m http.server`.
- Record the resolved image digest (`docker image inspect`) in the snapshot. Pulling by
  tag is acceptable for v1; the digest is the provenance.

**Container flags (must be asserted in tests).**

```
--rm (build) / -d (run)
--network=bridge (build) / --network=none (run)
--cap-drop=ALL
--security-opt=no-new-privileges
--read-only
--tmpfs /tmp:rw,exec
--user <host uid>:<host gid>
--memory=2g --cpus=2 --pids-limit=512
--ulimit nofile=4096
```

Never mount `/var/run/docker.sock`, never use `--privileged`, `--pid=host`,
`--ipc=host`, `--uts=host`, or `--device`. The only bind mount is the temp copy at
`/app`.

**UID and file ownership.** Run as the host UID/GID so the temp copy stays writable and
cleanup does not need root. Set `HOME=/tmp` so npm can write its cache. On Linux, the
temp copy is owned by the invoking user; on macOS Docker Desktop, the file-sharing layer
maps ownership. Test both if possible; document macOS as the primary dev platform.

**Snapshot determinism.** The tree hash walks the copied files in sorted path order,
hashes relative path + NUL + file bytes, and excludes the same generated trees as the
copy. Timestamps and container ids are metadata, not part of the tree hash. Two intakes
of the same clean commit produce the same tree hash and lockfile hash.

**Logs.** Capture stdout/stderr from build and run, cap at 1 MiB each, store as
`build.log` and `run.log` beside the snapshot with 0600. Do not upload them. They may
contain build-time secrets; that is local-only and documented. P5 will own redaction.

**Failure handling.** Every Docker call goes through a runner wrapper that maps nonzero
exit codes and timeouts to causes. A `finally` block always removes the container and
temp copy unless `--keep`. SIGINT sets the same cleanup path and exits 1.

**No new Python dependencies.** Use `subprocess`, `json`, `hashlib`, `shutil`,
`tempfile`, `pathlib`, `signal`, and `dataclasses`. Docker is an external CLI
requirement; `docker info` failures map to `DOCKER_UNAVAILABLE`.

## Risks & Open Questions

| Risk | Severity | Mitigation |
|---|---|---|
| **Docker is not a perfect security boundary.** A kernel escape or Docker bug could reach the host. | Med/High | Treat the threat model as "contain accidental damage and ordinary build scripts," not "contain a determined kernel attacker." Document this in README/ETHICS. |
| **Build scripts exfiltrate the repo during the network-enabled build.** `npm install` postinstall hooks run with network access and the copied tree. | Med/High | Only the temp copy is mounted; no host socket; no secrets beyond what the repo contains. `--offline-build` (S2) for vendored deps. Document that installing dependencies runs third-party code. |
| **Hanging or resource-heavy builds.** | Med/Med | Build timeout, memory/CPU/PID limits, capped logs. |
| **Orphan containers on SIGKILL.** `finally` cannot run on SIGKILL. | Low/Med | Snapshot records the container id; `--keep` prints the cleanup command; document `docker rm -f`. |
| **Large repos fill the disk during copy.** | Med/Low | Exclude generated trees; document; future size cap. |
| **macOS/Linux UID differences break writes.** | Med/Low | Run as host UID/GID, `HOME=/tmp`, integration tests on macOS; document Linux differences. |
| **Secrets in `.env` or build logs.** | Med/Med | The snapshot records hashes, not file contents; logs are local, capped, 0600; no upload. |

Open questions:

- Should `--keep` be part of the first release or a debug-only flag? (Plan: include it; it is how P3 will hold a sandbox open.)
- Should the run container expose a Unix socket or sidecar for P3, or should P3 use `docker exec`? (For P2, readiness uses `docker exec`; P3 can decide its probe transport.)
- Should the run phase use `--network=none` plus `docker exec`, or an internal network with a probe sidecar? (Recommend `none` + exec for the smallest attack surface.)

**The hard question before greenlighting:** a build phase that runs `npm install` is
arbitrary third-party code execution with network access. Is the user's trust model
"the repo and its dependencies are mine/trusted," or does P2 need a default
`--offline-build` that refuses to install anything over the network? This PRD assumes
the former, with an opt-in offline mode; confirm.

## Out of Scope

- Live URL intake and P1-token plumbing for URLs.
- Any probe, exploit, proof, finding, or verdict logic.
- Python/FastAPI, Django, Flask, Ruby, Go, or other runtimes.
- yarn, pnpm, Bun, or other package managers.
- Remote, hosted, or rootless sandbox backends.
- Windows support.
- Write-based or destructive actions.
- Custom seccomp/AppArmor profiles beyond Docker defaults.

## Acceptance Tests

| ID | Test | Expected |
|---|---|---|
| AT1 | Missing path | `REPO_NOT_FOUND`, exit 1 |
| AT2 | Directory with no `index.html` and no usable `package.json` | `UNSUPPORTED_PROJECT`, exit 1 |
| AT3 | Docker unavailable (fake `docker info` failure) | `DOCKER_UNAVAILABLE`, no temp/container |
| AT4 | Static fixture | Sandbox ready, snapshot kind `static`, port 8000 |
| AT5 | Node fixture with `start` script | Sandbox ready, snapshot kind `node`, port 3000 |
| AT6 | Node fixture with `build` then `start` | Both commands recorded and executed |
| AT7 | Build exits nonzero | `BUILD_FAILED`, no container, temp removed |
| AT8 | App never becomes ready | `READY_TIMEOUT`, container removed |
| AT9 | Run-phase fixture tries to fetch `https://example.com` | Request fails; snapshot records `network: none` |
| AT10 | Host repo after intake | Git status and tree hash unchanged |
| AT11 | Snapshot fields | Version, target, commit, dirty, tree hash, lockfile hash, image digest, commands, port, container id, timestamps |
| AT12 | Same clean tree, two intakes | Same tree hash and lockfile hash |
| AT13 | `--keep` | Container remains; output includes id and cleanup command |
| AT14 | SIGINT during build | `INTERRUPTED`, cleanup runs |
| AT15 | Default suite | Zero Docker calls; integration tests skipped unless `PRY_DOCKER_TESTS=1` |
| AT16 | Docs | README/architecture/roadmap state P2 local intake only; live URL deferred; no probe claim |

## Self-Critique

- 🟡 **The Docker boundary is weaker than it sounds.** It contains accidents and ordinary
  build scripts, not a kernel attacker. This must be stated plainly in the README and
  ETHICS.md.
- 🟡 **Build-time network access is the biggest residual risk.** A malicious dependency
  can exfiltrate the copied repo. The user owns the repo, but a compromised package is
  realistic. `--offline-build` is a should-have, not a default.
- 🟡 **Framework coverage is intentionally narrow.** Static + npm-based Node/Next. That
  matches the vibe-coded market; Python and other package managers wait.
- 🟢 **The snapshot is concrete and testable**, and every failure has a named cause.
