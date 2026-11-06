"""Run Docker behind one wrapper that never hands it the host."""

import os
import subprocess
import time
from dataclasses import dataclass
from typing import List, Optional, Sequence

from pry.intake.errors import (
    BUILD_FAILED,
    DOCKER_UNAVAILABLE,
    READY_TIMEOUT,
    SANDBOX_ERROR,
    START_FAILED,
    IntakeError,
)

DOCKER = "docker"
BUILD_TIMEOUT = 600
START_TIMEOUT = 60
READY_TIMEOUT_SECONDS = 60
READY_INTERVAL = 0.5

_DAEMON_MARKERS = (
    "cannot connect to the docker daemon",
    "is the docker daemon running",
    "error during connect",
)

_NODE_READY = (
    'fetch("http://127.0.0.1:%d/").then('
    "function () { process.exit(0); }, "
    "function () { process.exit(1); });"
)

_STATIC_READY = (
    "import sys, urllib.request, urllib.error\n"
    "try:\n"
    "    urllib.request.urlopen('http://127.0.0.1:%d/', timeout=2)\n"
    "except urllib.error.HTTPError:\n"
    "    sys.exit(0)\n"
    "except Exception:\n"
    "    sys.exit(1)\n"
)


def readiness_command(kind: str, port: int) -> List[str]:
    """Return the in-container command that probes 127.0.0.1:<port>."""
    if kind == "node":
        return ["node", "-e", _NODE_READY % port]
    if kind == "static":
        return ["python", "-c", _STATIC_READY % port]
    raise IntakeError(SANDBOX_ERROR, "unknown project kind: %s" % kind)


@dataclass(frozen=True)
class CommandResult:
    returncode: int
    stdout: bytes = b""
    stderr: bytes = b""
    timed_out: bool = False


def _as_bytes(value) -> bytes:
    if value is None:
        return b""
    if isinstance(value, bytes):
        return value
    return str(value).encode("utf-8", "replace")


class SubprocessRunner:
    """Run an argv without a shell; a timeout is data, not an exception."""

    def run(self, args: Sequence[str], timeout: float) -> CommandResult:
        try:
            completed = subprocess.run(
                list(args),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=timeout,
            )
        except subprocess.TimeoutExpired as exc:
            return CommandResult(
                -1, _as_bytes(exc.stdout), _as_bytes(exc.stderr), True
            )
        except OSError as exc:
            return CommandResult(-1, b"", str(exc).encode("utf-8", "replace"), False)
        return CommandResult(
            completed.returncode, completed.stdout, completed.stderr, False
        )


def _host_id(name: str) -> int:
    getter = getattr(os, name, None)
    return getter() if getter is not None else 0


def _detail(result: CommandResult) -> str:
    raw = result.stderr or result.stdout
    text = raw.decode("utf-8", "replace").strip()
    return text or "exit code %d" % result.returncode


def _daemon_down(result: CommandResult) -> bool:
    text = (result.stderr + result.stdout).decode("utf-8", "replace").lower()
    return any(marker in text for marker in _DAEMON_MARKERS)


class DockerRunner:
    def __init__(
        self,
        runner: Optional[SubprocessRunner] = None,
        uid: Optional[int] = None,
        gid: Optional[int] = None,
        memory: str = "2g",
        cpus: str = "2",
        pids: int = 512,
    ) -> None:
        self.runner = runner if runner is not None else SubprocessRunner()
        self.uid = _host_id("getuid") if uid is None else uid
        self.gid = _host_id("getgid") if gid is None else gid
        self.memory = memory
        self.cpus = cpus
        self.pids = pids

    def _run(self, args: List[str], timeout: float) -> CommandResult:
        return self.runner.run([DOCKER] + args, timeout)

    def _require_daemon(self, result: CommandResult) -> None:
        if _daemon_down(result):
            raise IntakeError(DOCKER_UNAVAILABLE, _detail(result))

    def _checked(
        self, args: List[str], timeout: float, cause: str, action: str
    ) -> CommandResult:
        result = self._run(args, timeout)
        self._require_daemon(result)
        if result.timed_out:
            raise IntakeError(cause, "%s timed out after %ss" % (action, timeout))
        if result.returncode != 0:
            raise IntakeError(cause, "%s failed: %s" % (action, _detail(result)))
        return result

    def _security_args(self) -> List[str]:
        return [
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges",
            "--read-only",
            "--tmpfs=/tmp:rw,exec",
            "--user=%d:%d" % (self.uid, self.gid),
            "--memory=%s" % self.memory,
            "--cpus=%s" % self.cpus,
            "--pids-limit=%d" % self.pids,
            "--ulimit=nofile=4096",
            "-e",
            "HOME=/tmp",
        ]

    def _mount_args(self, workspace) -> List[str]:
        return ["-v", "%s:/app" % workspace, "-w", "/app"]

    def available(self, timeout: float = 10) -> bool:
        result = self._run(["info"], timeout)
        return result.returncode == 0 and not result.timed_out

    def ensure_image(self, image: str, timeout: float = BUILD_TIMEOUT) -> str:
        self._checked(["pull", image], timeout, SANDBOX_ERROR, "docker pull %s" % image)
        result = self._checked(
            ["image", "inspect", "--format", "{{index .RepoDigests 0}}", image],
            timeout,
            SANDBOX_ERROR,
            "docker image inspect %s" % image,
        )
        digest = result.stdout.decode("utf-8", "replace").strip()
        if not digest:
            raise IntakeError(SANDBOX_ERROR, "no image digest for %s" % image)
        return digest

    def build(
        self,
        image: str,
        workspace,
        command: Sequence[str],
        timeout: float = BUILD_TIMEOUT,
    ) -> CommandResult:
        args = ["run", "--rm", "--network=bridge"]
        args += self._security_args()
        args += self._mount_args(workspace)
        args += [image]
        args += list(command)
        return self._checked(args, timeout, BUILD_FAILED, "build")

    def start(
        self,
        image: str,
        workspace,
        name: str,
        command: Sequence[str],
        port: int,
        timeout: float = START_TIMEOUT,
    ) -> str:
        args = ["run", "-d", "--name", name, "--network=none"]
        args += self._security_args()
        args += self._mount_args(workspace)
        args += ["-e", "PORT=%d" % port, image]
        args += list(command)
        result = self._checked(args, timeout, START_FAILED, "start")
        container_id = result.stdout.decode("utf-8", "replace").strip()
        if not container_id:
            raise IntakeError(START_FAILED, "docker start returned no container id")
        return container_id

    def exec(
        self, container: str, command: Sequence[str], timeout: float = 10
    ) -> CommandResult:
        result = self._run(["exec", container] + list(command), timeout)
        self._require_daemon(result)
        return result

    def _container_running(self, container: str) -> bool:
        result = self._run(
            ["inspect", "--format", "{{.State.Running}}", container], 10
        )
        self._require_daemon(result)
        return result.returncode == 0 and result.stdout.strip().lower() == b"true"

    def wait_ready(
        self,
        container: str,
        kind: str,
        port: int,
        timeout: float = READY_TIMEOUT_SECONDS,
        interval: float = READY_INTERVAL,
    ) -> None:
        command = readiness_command(kind, port)
        deadline = time.monotonic() + max(timeout, 0)
        while True:
            remaining = deadline - time.monotonic()
            exec_timeout = min(5.0, remaining) if remaining > 0 else 0.1
            result = self.exec(container, command, timeout=exec_timeout)
            if result.returncode == 0 and not result.timed_out:
                return
            if not self._container_running(container):
                raise IntakeError(
                    START_FAILED, "container exited before it became ready"
                )
            if time.monotonic() >= deadline:
                raise IntakeError(
                    READY_TIMEOUT,
                    "app in %s did not answer on port %d within %ss"
                    % (container, port, timeout),
                )
            time.sleep(interval)

    def logs(self, container: str, timeout: float = 10) -> bytes:
        result = self._run(["logs", container], timeout)
        self._require_daemon(result)
        if result.timed_out:
            raise IntakeError(SANDBOX_ERROR, "docker logs timed out")
        if result.returncode != 0:
            raise IntakeError(SANDBOX_ERROR, "docker logs failed: %s" % _detail(result))
        return result.stdout + result.stderr

    def remove(self, container: str, timeout: float = 30) -> None:
        result = self._run(["rm", "-f", container], timeout)
        self._require_daemon(result)
        if result.timed_out:
            raise IntakeError(SANDBOX_ERROR, "docker rm timed out")
        if result.returncode == 0:
            return
        detail = _detail(result)
        if "no such container" in detail.lower():
            return
        raise IntakeError(SANDBOX_ERROR, "docker rm failed: %s" % detail)
