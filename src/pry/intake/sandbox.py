"""Boot a local repository in a Docker sandbox and guarantee cleanup."""

import hashlib
import os
import shutil
import subprocess
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Optional

from pry.intake.docker import (
    BUILD_TIMEOUT,
    READY_TIMEOUT_SECONDS,
    CommandResult,
    DockerRunner,
)
from pry.intake.errors import (
    BUILD_FAILED,
    DOCKER_UNAVAILABLE,
    INTERRUPTED,
    REPO_NOT_FOUND,
    SANDBOX_ERROR,
    IntakeError,
)
from pry.intake.project import (
    ProjectSpec,
    copy_repo,
    detect_project,
    tree_sha256,
)
from pry.intake.snapshot import (
    new_run_dir,
    snapshot_id,
    utc_now,
    write_log,
    write_snapshot,
)

SNAPSHOT_VERSION = 1
BUILD_LOG = "build.log"
RUN_LOG = "run.log"


@dataclass(frozen=True)
class IntakeResult:
    snapshot_path: Path
    snapshot: dict
    container_id: Optional[str]
    workspace: Path
    kept: bool


@dataclass(frozen=True)
class SandboxHandle:
    container_id: str
    workspace: Path
    port: int
    kind: str
    sandbox_id: str


def _validated_path(path) -> Path:
    original = Path(path).expanduser()
    if not original.is_dir():
        raise IntakeError(REPO_NOT_FOUND, "not a directory: %s" % path)
    return original.resolve()


def _git(root: Path, *args) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", "-C", str(root)] + list(args),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=10,
    )


def _git_state(root: Path) -> dict:
    state = {"is_git": False, "git_commit": None, "git_dirty": None}
    try:
        inside = _git(root, "rev-parse", "--is-inside-work-tree")
        if inside.returncode != 0 or inside.stdout.strip() != b"true":
            return state
        state["is_git"] = True
        head = _git(root, "rev-parse", "HEAD")
        if head.returncode == 0:
            commit = head.stdout.decode("utf-8", "replace").strip()
            state["git_commit"] = commit or None
        status = _git(root, "status", "--porcelain")
        if status.returncode == 0:
            state["git_dirty"] = bool(status.stdout.strip())
    except (OSError, subprocess.SubprocessError):
        pass
    return state


def _apply_port(spec: ProjectSpec, port: Optional[int]) -> ProjectSpec:
    if port is None:
        return spec
    if spec.kind != "static":
        return replace(spec, port=port)
    try:
        start = list(spec.start)
        start[start.index("http.server") + 1] = str(port)
    except (ValueError, IndexError) as exc:
        raise IntakeError(SANDBOX_ERROR, "cannot apply port to static command") from exc
    return replace(spec, port=port, start=start)


def _lockfile(workspace: Path):
    path = Path(workspace) / "package-lock.json"
    if not path.is_file():
        return None, None
    try:
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError as exc:
        raise IntakeError(SANDBOX_ERROR, "cannot hash lockfile: %s" % exc) from exc
    return path.name, digest


def _host_user(docker) -> str:
    uid = getattr(docker, "uid", None)
    gid = getattr(docker, "gid", None)
    if uid is None:
        uid = os.getuid() if hasattr(os, "getuid") else 0
    if gid is None:
        gid = os.getgid() if hasattr(os, "getgid") else 0
    return "%d:%d" % (uid, gid)


def _limits(docker) -> dict:
    return {
        "memory": getattr(docker, "memory", "2g"),
        "cpus": getattr(docker, "cpus", "2"),
        "pids": getattr(docker, "pids", 512),
    }


def _output(result: CommandResult) -> bytes:
    return result.stdout + result.stderr


def _cleanup(docker, container, workspace, keep: bool):
    """Remove the container and workspace; report but never raise the failure."""
    if keep:
        return None
    error = None
    if container is not None:
        try:
            docker.remove(container)
        except Exception as exc:
            error = IntakeError(SANDBOX_ERROR, "cannot remove sandbox: %s" % exc)
    if workspace is not None and Path(workspace).exists():
        try:
            shutil.rmtree(str(workspace))
        except OSError as exc:
            if error is None:
                error = IntakeError(
                    SANDBOX_ERROR, "cannot remove workspace: %s" % exc
                )
    return error


def _record_failure(run_dir, snapshot, error, docker, container) -> None:
    """Write a best-effort failure snapshot without hiding the original error."""
    result = snapshot["result"]
    result.update(
        {"status": "failed", "cause": error.cause, "message": error.message}
    )
    if error.cause == BUILD_FAILED and result.get("build_log"):
        try:
            write_log(run_dir, BUILD_LOG, str(error).encode("utf-8", "replace"))
        except IntakeError:
            pass
    if container is not None:
        try:
            write_log(run_dir, RUN_LOG, docker.logs(container))
            result["run_log"] = RUN_LOG
        except Exception:
            pass
    try:
        write_snapshot(run_dir, snapshot)
    except IntakeError:
        pass


def intake(
    path,
    *,
    out=None,
    keep=False,
    port=None,
    timeout=None,
    docker=None,
    home=None,
    network=None,
    on_ready=None,
) -> IntakeResult:
    original = _validated_path(path)
    if port is not None and (not isinstance(port, int) or not 1 <= port <= 65535):
        raise IntakeError(SANDBOX_ERROR, "port must be between 1 and 65535")
    sandbox_id = snapshot_id()
    if out is None:
        base = Path(home) if home is not None else Path.home()
        run_dir = new_run_dir(base / ".pry" / "runs" / sandbox_id)
    else:
        run_dir = new_run_dir(out)
    created_at = utc_now()

    target = {
        "path": str(original),
        "kind": None,
        "git_commit": None,
        "git_dirty": None,
        "is_git": False,
        "tree_sha256": None,
    }
    project = {
        "package_manager": None,
        "lockfile": None,
        "lockfile_sha256": None,
        "image": None,
        "image_digest": None,
        "install": None,
        "build": None,
        "start": None,
        "port": None,
    }
    sandbox = {
        "network": "none",
        "build_network": "bridge",
        "user": None,
        "limits": None,
        "container_id": None,
        "workspace": None,
        "internal_url": None,
    }
    result = {
        "status": "failed",
        "cause": None,
        "message": None,
        "ready_at": None,
        "build_log": None,
        "run_log": None,
    }
    snapshot = {
        "version": SNAPSHOT_VERSION,
        "sandbox_id": sandbox_id,
        "created_at": created_at,
        "target": target,
        "project": project,
        "sandbox": sandbox,
        "result": result,
    }

    runner = docker if docker is not None else DockerRunner()
    workspace = None
    container = None
    start_attempted = False
    outcome = None
    error = None

    try:
        target.update(_git_state(original))

        workspace = copy_repo(original)
        sandbox["workspace"] = str(workspace)

        spec = _apply_port(detect_project(workspace), port)
        target["kind"] = spec.kind
        target["tree_sha256"] = tree_sha256(workspace)

        lockfile, lockfile_sha = _lockfile(workspace)
        project.update(
            {
                "package_manager": spec.package_manager,
                "lockfile": lockfile,
                "lockfile_sha256": lockfile_sha,
                "image": spec.image,
                "install": spec.install,
                "build": spec.build,
                "start": spec.start,
                "port": spec.port,
            }
        )
        sandbox["user"] = _host_user(runner)
        sandbox["limits"] = _limits(runner)
        if network:
            sandbox["network"] = network
            sandbox["internal_url"] = "http://app:%d" % spec.port
        else:
            sandbox["internal_url"] = "http://127.0.0.1:%d" % spec.port

        if not runner.available():
            raise IntakeError(DOCKER_UNAVAILABLE, "docker daemon is not available")
        project["image_digest"] = runner.ensure_image(spec.image)

        if spec.install or spec.build:
            result["build_log"] = BUILD_LOG
        build_output = b""
        if spec.install:
            build_output += _output(
                runner.build(spec.image, workspace, spec.install, BUILD_TIMEOUT)
            )
        if spec.build:
            build_output += _output(
                runner.build(spec.image, workspace, spec.build, BUILD_TIMEOUT)
            )
        if result["build_log"] is not None:
            write_log(run_dir, BUILD_LOG, build_output)

        start_attempted = True
        container = runner.start(
            spec.image,
            workspace,
            sandbox_id,
            spec.start,
            spec.port,
            network=network or "none",
            alias="app" if network else None,
        )
        sandbox["container_id"] = container
        ready_timeout = READY_TIMEOUT_SECONDS if timeout is None else timeout
        runner.wait_ready(container, spec.kind, spec.port, timeout=ready_timeout)

        if on_ready is not None:
            on_ready(
                SandboxHandle(
                    container_id=container,
                    workspace=workspace,
                    port=spec.port,
                    kind=spec.kind,
                    sandbox_id=sandbox_id,
                )
            )

        write_log(run_dir, RUN_LOG, runner.logs(container))
        result.update(
            {
                "status": "ready",
                "cause": None,
                "message": None,
                "ready_at": utc_now(),
                "run_log": RUN_LOG,
            }
        )
        snapshot_path = write_snapshot(run_dir, snapshot)
        outcome = IntakeResult(
            snapshot_path, snapshot, container, workspace, keep
        )
    except IntakeError as exc:
        error = exc
        _record_failure(run_dir, snapshot, exc, runner, container)
    except KeyboardInterrupt:
        error = IntakeError(INTERRUPTED, "intake interrupted")
        _record_failure(run_dir, snapshot, error, runner, container)
    except Exception as exc:
        error = IntakeError(
            SANDBOX_ERROR, "unexpected intake failure: %s" % exc
        )
        _record_failure(run_dir, snapshot, error, runner, container)
    finally:
        cleanup_error = _cleanup(
            runner,
            container
            if container is not None
            else (sandbox_id if start_attempted else None),
            workspace,
            keep,
        )

    if error is not None:
        raise error
    if cleanup_error is not None:
        raise cleanup_error
    return outcome
