"""Sandbox orchestration and cleanup tests (AT4-AT8/AT13/AT14).

Everything here uses a FakeDocker and a temp repo. No test may call the real
``docker`` binary or touch the network.
"""

import hashlib
import json
import shutil
import subprocess

import pytest

import pry.intake.sandbox as sandbox
from pry.intake.docker import CommandResult
from pry.intake.errors import (
    BUILD_FAILED,
    DOCKER_UNAVAILABLE,
    INTERRUPTED,
    READY_TIMEOUT,
    REPO_NOT_FOUND,
    SANDBOX_ERROR,
    START_FAILED,
    UNSUPPORTED_PROJECT,
    IntakeError,
)
from pry.intake.project import tree_sha256
from pry.intake.sandbox import IntakeResult, SandboxHandle, intake

DIGEST = "sha256:" + "a" * 64
CONTAINER = "container123"
STATIC_START = [
    "python",
    "-m",
    "http.server",
    "8000",
    "--directory",
    "/app",
    "--bind",
    "127.0.0.1",
]


class FakeDocker:
    """Records every sandbox call and fails on request, never on the host."""

    def __init__(
        self,
        available=True,
        fail_build=False,
        fail_start=False,
        fail_ready=False,
        fail_remove=False,
        interrupt_build=False,
        build_output=b"built\n",
        run_output=b"server up\n",
    ):
        self.is_available = available
        self.fail_build = fail_build
        self.fail_start = fail_start
        self.fail_ready = fail_ready
        self.fail_remove = fail_remove
        self.interrupt_build = interrupt_build
        self.build_output = build_output
        self.run_output = run_output
        self.uid = 501
        self.gid = 20
        self.memory = "2g"
        self.cpus = "2"
        self.pids = 512
        self.calls = []
        self.removed = []

    def available(self):
        self.calls.append(("available",))
        return self.is_available

    def ensure_image(self, image):
        self.calls.append(("ensure_image", image))
        return DIGEST

    def build(self, image, workspace, command, timeout=600):
        self.calls.append(("build", list(command), timeout))
        if self.interrupt_build:
            raise KeyboardInterrupt()
        if self.fail_build:
            raise IntakeError(BUILD_FAILED, "npm ERR!")
        return CommandResult(0, self.build_output, b"", False)

    def start(
        self, image, workspace, name, command, port, timeout=60,
        network="none", alias=None,
    ):
        self.calls.append(
            (
                "start", image, str(workspace), name, list(command), port,
                network, alias,
            )
        )
        if self.fail_start:
            raise IntakeError(START_FAILED, "boom")
        return CONTAINER

    def wait_ready(self, container, kind, port, timeout=60):
        self.calls.append(("wait_ready", container, kind, port, timeout))
        if self.fail_ready:
            raise IntakeError(READY_TIMEOUT, "never ready")

    def logs(self, container):
        self.calls.append(("logs", container))
        return self.run_output

    def remove(self, container):
        self.calls.append(("remove", container))
        if self.fail_remove:
            raise IntakeError(SANDBOX_ERROR, "cannot remove")
        self.removed.append(container)


def _static_repo(root):
    root.mkdir(parents=True, exist_ok=True)
    (root / "index.html").write_text("<h1>hi</h1>")
    return root


def _node_repo(root, scripts, lockfile=None):
    root.mkdir(parents=True, exist_ok=True)
    (root / "package.json").write_text(json.dumps({"scripts": scripts}))
    if lockfile is not None:
        (root / "package-lock.json").write_text(lockfile)
    return root


def _snapshot(run_dir):
    return json.loads((run_dir / "snapshot.json").read_text())


def _call(fake, name):
    matches = [call for call in fake.calls if call[0] == name]
    assert matches, "no %s call in %r" % (name, fake.calls)
    return matches


def _has(fake, name):
    return any(call[0] == name for call in fake.calls)


@pytest.fixture
def copied(monkeypatch):
    """Record every workspace copy so failure tests can assert its deletion."""
    seen = []
    real_copy = sandbox.copy_repo

    def record(src):
        workspace = real_copy(src)
        seen.append(workspace)
        return workspace

    monkeypatch.setattr(sandbox, "copy_repo", record)
    return seen


@pytest.mark.parametrize("kind", ["missing", "file"])
def test_bad_path_is_repo_not_found_and_creates_no_run_dir(tmp_path, kind):
    path = tmp_path / "nope"
    if kind == "file":
        path.write_text("not a directory")
    out = tmp_path / "run"

    with pytest.raises(IntakeError) as exc:
        intake(str(path), out=out, docker=FakeDocker())

    assert exc.value.cause == REPO_NOT_FOUND
    assert not out.exists()


def test_unsupported_project_fails_cleanly(tmp_path, copied):
    repo = tmp_path / "empty"
    repo.mkdir()
    out = tmp_path / "run"
    fake = FakeDocker()

    with pytest.raises(IntakeError) as exc:
        intake(str(repo), out=out, docker=fake)

    assert exc.value.cause == UNSUPPORTED_PROJECT
    assert not copied[0].exists()
    assert not _has(fake, "start")
    assert _snapshot(out)["result"]["cause"] == UNSUPPORTED_PROJECT


def test_docker_unavailable_creates_no_container(tmp_path, copied):
    repo = _static_repo(tmp_path / "repo")
    out = tmp_path / "run"
    fake = FakeDocker(available=False)

    with pytest.raises(IntakeError) as exc:
        intake(str(repo), out=out, docker=fake)

    assert exc.value.cause == DOCKER_UNAVAILABLE
    assert not copied[0].exists()
    assert not _has(fake, "ensure_image")
    assert not _has(fake, "start")
    assert _snapshot(out)["result"]["cause"] == DOCKER_UNAVAILABLE


def test_static_success_writes_ready_snapshot_and_cleans_up(tmp_path):
    repo = _static_repo(tmp_path / "repo")
    before = tree_sha256(repo)
    out = tmp_path / "run"
    fake = FakeDocker()

    result = intake(str(repo), out=out, docker=fake)

    assert isinstance(result, IntakeResult)
    assert result.snapshot_path == out / "snapshot.json"
    assert result.snapshot_path.is_file()
    assert result.container_id == CONTAINER
    assert result.kept is False
    assert not result.workspace.exists()
    assert fake.removed == [CONTAINER]

    data = _snapshot(out)
    assert result.snapshot == data
    assert set(data) == {
        "version",
        "sandbox_id",
        "created_at",
        "target",
        "project",
        "sandbox",
        "result",
    }
    assert data["version"] == 1
    assert data["sandbox_id"].startswith("pry-")
    assert data["created_at"].endswith("Z")

    target = data["target"]
    assert target == {
        "path": str(repo.resolve()),
        "kind": "static",
        "git_commit": None,
        "git_dirty": None,
        "is_git": False,
        "tree_sha256": before,
    }

    project = data["project"]
    assert project == {
        "package_manager": None,
        "lockfile": None,
        "lockfile_sha256": None,
        "image": "python:3.9-slim",
        "image_digest": DIGEST,
        "install": None,
        "build": None,
        "start": STATIC_START,
        "port": 8000,
    }

    sandbox_data = data["sandbox"]
    assert sandbox_data["network"] == "none"
    assert sandbox_data["build_network"] == "bridge"
    assert sandbox_data["user"] == "501:20"
    assert sandbox_data["limits"] == {"memory": "2g", "cpus": "2", "pids": 512}
    assert sandbox_data["container_id"] == CONTAINER
    assert sandbox_data["workspace"] == str(result.workspace)
    assert sandbox_data["internal_url"] == "http://127.0.0.1:8000"

    outcome = data["result"]
    assert outcome["status"] == "ready"
    assert outcome["cause"] is None
    assert outcome["message"] is None
    assert outcome["ready_at"].endswith("Z")
    assert outcome["build_log"] is None
    assert outcome["run_log"] == "run.log"
    assert (out / "run.log").read_bytes() == b"server up\n"

    start_call = _call(fake, "start")[0]
    assert start_call[1] == "python:3.9-slim"
    assert start_call[3].startswith("pry-")
    assert start_call[4] == STATIC_START
    assert start_call[5] == 8000
    assert start_call[6:] == ("none", None)
    ready_call = _call(fake, "wait_ready")[0]
    assert ready_call[1:] == (CONTAINER, "static", 8000, 60)

    assert tree_sha256(repo) == before


def test_probe_network_starts_the_app_with_the_alias_and_records_url(tmp_path):
    repo = _static_repo(tmp_path / "repo")
    out = tmp_path / "run"
    fake = FakeDocker()

    result = intake(str(repo), out=out, network="pry-abc", docker=fake)

    start_call = _call(fake, "start")[0]
    assert start_call[6] == "pry-abc"
    assert start_call[7] == "app"
    data = _snapshot(out)
    assert data["sandbox"]["network"] == "pry-abc"
    assert data["sandbox"]["internal_url"] == "http://app:8000"
    assert not result.workspace.exists()


def test_on_ready_receives_a_handle_before_the_success_snapshot(tmp_path):
    repo = _static_repo(tmp_path / "repo")
    out = tmp_path / "run"
    fake = FakeDocker()
    seen = []

    def on_ready(handle):
        assert fake.calls[-1][0] == "wait_ready"
        assert not (out / "run.log").exists()
        assert not (out / "snapshot.json").exists()
        seen.append(handle)

    result = intake(str(repo), out=out, on_ready=on_ready, docker=fake)

    assert seen == [
        SandboxHandle(
            CONTAINER, result.workspace, 8000, "static", result.snapshot["sandbox_id"]
        )
    ]
    assert fake.removed == [CONTAINER]
    assert not result.workspace.exists()


def test_on_ready_failure_cleans_up_and_records_the_failure(tmp_path, copied):
    repo = _static_repo(tmp_path / "repo")
    out = tmp_path / "run"
    fake = FakeDocker()

    def on_ready(handle):
        raise RuntimeError("sidecar did not start")

    with pytest.raises(IntakeError) as exc:
        intake(str(repo), out=out, on_ready=on_ready, docker=fake)

    assert exc.value.cause == SANDBOX_ERROR
    assert fake.removed == [CONTAINER]
    assert not copied[0].exists()
    data = _snapshot(out)
    assert data["result"]["status"] == "failed"
    assert data["result"]["cause"] == SANDBOX_ERROR


def test_default_run_dir_matches_sandbox_id(tmp_path):
    repo = _static_repo(tmp_path / "repo")

    result = intake(str(repo), home=tmp_path, docker=FakeDocker())

    assert result.snapshot_path.parent.name == result.snapshot["sandbox_id"]


@pytest.mark.parametrize("port", [0, -1, 70000])
def test_invalid_port_is_rejected(tmp_path, port):
    repo = _static_repo(tmp_path / "repo")

    with pytest.raises(IntakeError) as exc:
        intake(str(repo), out=tmp_path / "run", port=port, docker=FakeDocker())

    assert exc.value.cause == SANDBOX_ERROR


def test_port_override_rebuilds_the_static_start_command(tmp_path):
    repo = _static_repo(tmp_path / "repo")
    out = tmp_path / "run"
    fake = FakeDocker()

    intake(str(repo), out=out, port=9123, docker=fake)

    data = _snapshot(out)
    expected = [
        "python",
        "-m",
        "http.server",
        "9123",
        "--directory",
        "/app",
        "--bind",
        "127.0.0.1",
    ]
    assert data["project"]["start"] == expected
    assert data["project"]["port"] == 9123
    assert data["sandbox"]["internal_url"] == "http://127.0.0.1:9123"
    assert _call(fake, "start")[0][4] == expected
    assert _call(fake, "start")[0][5] == 9123
    assert _call(fake, "wait_ready")[0][3] == 9123


def test_node_runs_install_then_build_then_start(tmp_path):
    repo = _node_repo(
        tmp_path / "repo",
        {"build": "next build", "start": "next start"},
        lockfile="{}",
    )
    out = tmp_path / "run"
    fake = FakeDocker()

    result = intake(str(repo), out=out, docker=fake)

    commands = [call[1] for call in _call(fake, "build")]
    assert commands == [["npm", "ci"], ["npm", "run", "build"]]
    assert [call[2] for call in _call(fake, "build")] == [600, 600]

    data = _snapshot(out)
    assert data["target"]["kind"] == "node"
    assert data["project"]["package_manager"] == "npm"
    assert data["project"]["lockfile"] == "package-lock.json"
    assert data["project"]["lockfile_sha256"] == hashlib.sha256(b"{}").hexdigest()
    assert data["project"]["install"] == ["npm", "ci"]
    assert data["project"]["build"] == ["npm", "run", "build"]
    assert data["project"]["start"] == ["npm", "run", "start"]
    assert data["project"]["port"] == 3000
    assert data["result"]["build_log"] == "build.log"
    assert (out / "build.log").read_bytes() == b"built\nbuilt\n"
    assert _call(fake, "start")[0][4] == ["npm", "run", "start"]
    assert _call(fake, "start")[0][5] == 3000
    assert not result.workspace.exists()


def test_node_port_override_keeps_the_command(tmp_path):
    repo = _node_repo(tmp_path / "repo", {"start": "node server.js"})
    out = tmp_path / "run"
    fake = FakeDocker()

    intake(str(repo), out=out, port=4321, docker=fake)

    data = _snapshot(out)
    assert data["project"]["start"] == ["npm", "run", "start"]
    assert data["project"]["port"] == 4321
    assert _call(fake, "start")[0][4] == ["npm", "run", "start"]
    assert _call(fake, "start")[0][5] == 4321


def test_build_failure_writes_a_failure_snapshot_and_removes_workspace(
    tmp_path, copied
):
    repo = _node_repo(
        tmp_path / "repo", {"build": "next build", "start": "next start"}
    )
    out = tmp_path / "run"
    fake = FakeDocker(fail_build=True)

    with pytest.raises(IntakeError) as exc:
        intake(str(repo), out=out, docker=fake)

    assert exc.value.cause == BUILD_FAILED
    assert not copied[0].exists()
    assert not _has(fake, "start")
    data = _snapshot(out)
    assert data["result"]["status"] == "failed"
    assert data["result"]["cause"] == BUILD_FAILED
    assert data["result"]["build_log"] == "build.log"
    assert b"npm ERR!" in (out / "build.log").read_bytes()


def test_start_failure_removes_the_started_name(tmp_path, copied):
    repo = _static_repo(tmp_path / "repo")
    out = tmp_path / "run"
    fake = FakeDocker(fail_start=True)

    with pytest.raises(IntakeError) as exc:
        intake(str(repo), out=out, docker=fake)

    assert exc.value.cause == START_FAILED
    assert not copied[0].exists()
    name = _call(fake, "start")[0][3]
    assert fake.removed == [name]
    assert _snapshot(out)["result"]["cause"] == START_FAILED


def test_readiness_timeout_removes_container_and_captures_run_log(
    tmp_path, copied
):
    repo = _static_repo(tmp_path / "repo")
    out = tmp_path / "run"
    fake = FakeDocker(fail_ready=True, run_output=b"starting\n")

    with pytest.raises(IntakeError) as exc:
        intake(str(repo), out=out, docker=fake)

    assert exc.value.cause == READY_TIMEOUT
    assert not copied[0].exists()
    assert fake.removed == [CONTAINER]
    data = _snapshot(out)
    assert data["result"]["cause"] == READY_TIMEOUT
    assert data["result"]["run_log"] == "run.log"
    assert (out / "run.log").read_bytes() == b"starting\n"


def test_keep_preserves_the_container_and_workspace(tmp_path):
    repo = _static_repo(tmp_path / "repo")
    out = tmp_path / "run"
    fake = FakeDocker()

    result = intake(str(repo), out=out, keep=True, docker=fake)

    assert result.kept is True
    assert result.container_id == CONTAINER
    assert result.workspace.exists()
    assert fake.removed == []
    assert _snapshot(out)["sandbox"]["workspace"] == str(result.workspace)

    shutil.rmtree(str(result.workspace), ignore_errors=True)


def test_keyboard_interrupt_maps_to_interrupted_and_cleans_up(tmp_path, copied):
    repo = _node_repo(tmp_path / "repo", {"start": "node server.js"})
    out = tmp_path / "run"
    fake = FakeDocker(interrupt_build=True)

    with pytest.raises(IntakeError) as exc:
        intake(str(repo), out=out, docker=fake)

    assert exc.value.cause == INTERRUPTED
    assert not copied[0].exists()
    assert not _has(fake, "start")
    assert _snapshot(out)["result"]["cause"] == INTERRUPTED


def test_cleanup_failure_does_not_mask_the_original_error(tmp_path, copied):
    repo = _static_repo(tmp_path / "repo")
    out = tmp_path / "run"
    fake = FakeDocker(fail_ready=True, fail_remove=True)

    with pytest.raises(IntakeError) as exc:
        intake(str(repo), out=out, docker=fake)

    assert exc.value.cause == READY_TIMEOUT
    assert not copied[0].exists()


def test_build_and_run_logs_are_capped(tmp_path):
    repo = _node_repo(
        tmp_path / "repo", {"build": "next build", "start": "next start"}
    )
    out = tmp_path / "run"
    fake = FakeDocker(
        build_output=b"b" * (2 * 1024 * 1024),
        run_output=b"r" * (2 * 1024 * 1024),
    )

    intake(str(repo), out=out, docker=fake)

    for name in ("build.log", "run.log"):
        body = (out / name).read_bytes()
        assert len(body) <= 1024 * 1024
        assert b"truncated" in body


def _git(root, *args):
    return subprocess.run(
        ["git", "-C", str(root)] + list(args),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def test_git_state_is_recorded_from_the_original_before_copying(tmp_path):
    if shutil.which("git") is None:
        pytest.skip("git is not installed")
    repo = _static_repo(tmp_path / "repo")
    _git(repo, "init", "-q")
    _git(repo, "add", "index.html")
    _git(
        repo,
        "-c",
        "user.email=pry@example.invalid",
        "-c",
        "user.name=Pry",
        "commit",
        "-qm",
        "init",
    )
    commit = _git(repo, "rev-parse", "HEAD").stdout.decode().strip()
    before = tree_sha256(repo)

    intake(str(repo), out=tmp_path / "clean-run", docker=FakeDocker())
    clean = _snapshot(tmp_path / "clean-run")["target"]

    assert clean["is_git"] is True
    assert clean["git_commit"] == commit
    assert clean["git_dirty"] is False
    assert clean["tree_sha256"] == before

    (repo / "index.html").write_text("<h1>changed</h1>")
    dirty_before = tree_sha256(repo)
    intake(str(repo), out=tmp_path / "dirty-run", docker=FakeDocker())
    dirty = _snapshot(tmp_path / "dirty-run")["target"]

    assert dirty["is_git"] is True
    assert dirty["git_commit"] == commit
    assert dirty["git_dirty"] is True
    assert dirty["tree_sha256"] == dirty_before
    assert tree_sha256(repo) == dirty_before
