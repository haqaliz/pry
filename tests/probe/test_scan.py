"""Local scan orchestration and cleanup tests (AT7-AT12).

Every test uses a fake intake and a fake docker. Nothing here starts a real
container, calls the ``docker`` binary, or touches the network.
"""

import json
import re
import stat
from pathlib import Path

import pytest

import pry.probe.scan as scan
from pry.intake import IntakeResult, SandboxHandle
from pry.intake.docker import CommandResult
from pry.intake.errors import (
    BUILD_FAILED,
    REPO_NOT_FOUND,
    SANDBOX_ERROR,
    IntakeError,
)
from pry.probe.results import (
    EXPOSED,
    NOT_REPRODUCED,
    UNVERIFIED,
    ProbeError,
    ProbeResult,
    summarize,
)
from pry.probe.scan import INVALID_ENDPOINT, ScanOutcome

SANDBOX_ID = "pry-0123456789ab"
SIDECAR = "pry-probe-" + SANDBOX_ID
PORT = 8000
BASE = "http://app:%d" % PORT


class FakeDocker:
    """Records sandbox calls and scripts probe responses per probe name."""

    def __init__(
        self,
        responses=None,
        fail_network_remove=False,
        fail_sidecar_remove=False,
    ):
        self.responses = dict(responses or {})
        self.fail_network_remove = fail_network_remove
        self.fail_sidecar_remove = fail_sidecar_remove
        self.calls = []
        self.networks = []
        self.sidecars = []

    def create_network(self, name):
        self.calls.append(("create_network", name))
        self.networks.append(name)

    def remove_network(self, name):
        self.calls.append(("remove_network", name))
        if self.fail_network_remove:
            raise IntakeError(SANDBOX_ERROR, "network remove failed")
        if name in self.networks:
            self.networks.remove(name)

    def start_sidecar(self, network, name, script):
        self.calls.append(("start_sidecar", network, name, str(script)))
        self.sidecars.append(name)
        return "sidecar123"

    def remove(self, container):
        self.calls.append(("remove", container))
        if self.fail_sidecar_remove:
            raise IntakeError(SANDBOX_ERROR, "container remove failed")
        if container in self.sidecars:
            self.sidecars.remove(container)

    def exec(self, container, command, timeout=10):
        self.calls.append(("exec", container, list(command), timeout))
        probe = command[2]
        response = self.responses.get(probe)
        if response is None:
            response = _payload(probe)
        if isinstance(response, Exception):
            raise response
        if isinstance(response, CommandResult):
            return response
        return CommandResult(0, json.dumps(response).encode("utf-8"), b"", False)


class FakeIntake:
    """Stand-in for pry.intake.intake; calls on_ready with a real handle."""

    def __init__(self, snapshot, fail=None):
        self.snapshot = snapshot
        self.fail = fail
        self.calls = []

    def __call__(self, path, **kwargs):
        self.calls.append((path, kwargs))
        run_dir = Path(kwargs["out"])
        run_dir.mkdir(parents=True, exist_ok=True)
        if self.fail is not None:
            raise self.fail
        kwargs["on_ready"](
            SandboxHandle(
                container_id="app123",
                workspace=run_dir / "workspace",
                port=PORT,
                kind=self.snapshot["target"]["kind"],
                sandbox_id=self.snapshot["sandbox_id"],
            )
        )
        return IntakeResult(
            snapshot_path=run_dir / "snapshot.json",
            snapshot=self.snapshot,
            container_id="app123",
            workspace=run_dir / "workspace",
            kept=False,
        )


class ExplodingClient:
    """A client whose probe run raises instead of returning results."""

    def __init__(self, docker, sidecar, base_url):
        pass

    def run_all(self):
        raise RuntimeError("probe crashed")


def _snapshot(path="/repo", kind="static"):
    return {
        "version": 1,
        "sandbox_id": SANDBOX_ID,
        "created_at": "2026-11-07T00:00:00Z",
        "target": {"path": path, "kind": kind},
        "project": {},
        "sandbox": {},
        "result": {},
    }


def _payload(probe, verdict=NOT_REPRODUCED):
    return {
        "probe": probe,
        "verdict": verdict,
        "cause": None,
        "evidence": "%s checked" % probe,
        "request": {
            "method": "GET",
            "url": BASE + "/",
            "headers": {"User-Agent": "pry/0.1"},
        },
        "response": {"status": 200, "headers": {}, "body": "ok"},
    }


@pytest.fixture
def repo(tmp_path):
    path = tmp_path / "repo"
    path.mkdir()
    return path


def _network_of(docker):
    created = [call for call in docker.calls if call[0] == "create_network"]
    assert len(created) == 1, docker.calls
    return created[0][1]


def test_scan_creates_a_per_run_network_and_passes_it_to_intake(
    repo, tmp_path, monkeypatch
):
    docker = FakeDocker()
    fake = FakeIntake(_snapshot())
    monkeypatch.setattr(scan, "intake", fake)

    scan.scan_local(repo, out=tmp_path / "run", docker=docker)

    network = _network_of(docker)
    assert re.fullmatch(r"pry-net-[0-9a-f]{12}", network)
    path, kwargs = fake.calls[0]
    assert str(path) == str(repo)
    assert kwargs["out"] == tmp_path / "run"
    assert kwargs["port"] is None
    assert kwargs["timeout"] is None
    assert kwargs["docker"] is docker
    assert kwargs["network"] == network
    assert callable(kwargs["on_ready"])
    assert docker.networks == []


def test_scan_starts_the_sidecar_on_the_network_and_runs_every_probe(
    repo, tmp_path, monkeypatch
):
    docker = FakeDocker()
    fake = FakeIntake(_snapshot())
    monkeypatch.setattr(scan, "intake", fake)

    outcome = scan.scan_local(repo, out=tmp_path / "run", docker=docker)

    network = _network_of(docker)
    started = [call for call in docker.calls if call[0] == "start_sidecar"]
    assert started == [
        (
            "start_sidecar",
            network,
            SIDECAR,
            str(Path(scan.__file__).with_name("sidecar.py")),
        )
    ]
    assert scan.sidecar_script_path() == Path(scan.__file__).with_name("sidecar.py")
    assert scan.sidecar_script_path().is_file()

    exec_calls = [call for call in docker.calls if call[0] == "exec"]
    assert [call[2] for call in exec_calls] == [
        ["python", "/pry/sidecar.py", "cors", BASE],
        ["python", "/pry/sidecar.py", "errors", BASE],
        ["python", "/pry/sidecar.py", "secrets", BASE],
    ]
    assert all(call[1] == SIDECAR for call in exec_calls)
    assert all(call[3] == 20 for call in exec_calls)
    assert ("remove", SIDECAR) in docker.calls
    assert docker.sidecars == []
    assert [result.probe for result in outcome.results] == [
        "cors",
        "errors",
        "secrets",
    ]


def test_scan_returns_the_snapshot_results_and_summary(repo, tmp_path, monkeypatch):
    docker = FakeDocker(
        responses={
            "cors": _payload("cors", EXPOSED),
            "errors": _payload("errors", NOT_REPRODUCED),
            "secrets": _payload("secrets", UNVERIFIED),
        }
    )
    snapshot = _snapshot()
    fake = FakeIntake(snapshot)
    monkeypatch.setattr(scan, "intake", fake)

    outcome = scan.scan_local(repo, out=tmp_path / "run", docker=docker)

    assert isinstance(outcome, ScanOutcome)
    assert outcome.snapshot == snapshot
    assert outcome.results_path == tmp_path / "run" / "results.json"
    assert [result.probe for result in outcome.results] == [
        "cors",
        "errors",
        "secrets",
    ]
    assert all(isinstance(result, ProbeResult) for result in outcome.results)
    assert outcome.summary == {EXPOSED: 1, NOT_REPRODUCED: 1, UNVERIFIED: 1}
    assert outcome.summary == summarize(outcome.results)


def test_scan_writes_results_json_beside_the_snapshot(repo, tmp_path, monkeypatch):
    docker = FakeDocker(
        responses={
            "cors": _payload("cors", EXPOSED),
            "errors": _payload("errors", NOT_REPRODUCED),
            "secrets": _payload("secrets", EXPOSED),
        }
    )
    fake = FakeIntake(_snapshot())
    monkeypatch.setattr(scan, "intake", fake)

    outcome = scan.scan_local(repo, out=tmp_path / "run", docker=docker)

    assert outcome.results_path == tmp_path / "run" / "results.json"
    assert stat.S_IMODE(outcome.results_path.stat().st_mode) == 0o600
    data = json.loads(outcome.results_path.read_text())
    assert set(data) == {"version", "target", "results", "summary", "created_at"}
    assert data["version"] == 1
    assert data["target"] == {
        "sandbox_id": SANDBOX_ID,
        "path": "/repo",
        "kind": "static",
    }
    assert [result["probe"] for result in data["results"]] == [
        "cors",
        "errors",
        "secrets",
    ]
    assert data["summary"] == {EXPOSED: 2, NOT_REPRODUCED: 1, UNVERIFIED: 0}
    assert data["created_at"].endswith("Z")
    for entry in data["results"]:
        assert set(entry) == {
            "probe",
            "verdict",
            "cause",
            "evidence",
            "request",
            "response",
        }
        assert entry["request"]["headers"] == {"user-agent": "pry/0.1"}


def test_scan_records_a_failed_probe_as_unverified_and_continues(
    repo, tmp_path, monkeypatch
):
    docker = FakeDocker(
        responses={
            "cors": _payload("cors", EXPOSED),
            "errors": CommandResult(1, b"", b"probe exploded", False),
            "secrets": _payload("secrets", NOT_REPRODUCED),
        }
    )
    fake = FakeIntake(_snapshot())
    monkeypatch.setattr(scan, "intake", fake)

    outcome = scan.scan_local(repo, out=tmp_path / "run", docker=docker)

    assert [result.verdict for result in outcome.results] == [
        EXPOSED,
        UNVERIFIED,
        NOT_REPRODUCED,
    ]
    assert outcome.results[1].cause == "EXEC_FAILED"
    assert outcome.summary == {EXPOSED: 1, NOT_REPRODUCED: 1, UNVERIFIED: 1}
    assert outcome.results_path.exists()
    assert [call[2][2] for call in docker.calls if call[0] == "exec"] == [
        "cors",
        "errors",
        "secrets",
    ]
    assert docker.sidecars == []
    assert docker.networks == []


def test_scan_rejects_a_missing_path_before_touching_docker(
    tmp_path, monkeypatch
):
    docker = FakeDocker()
    fake = FakeIntake(_snapshot())
    monkeypatch.setattr(scan, "intake", fake)

    with pytest.raises(IntakeError) as exc:
        scan.scan_local(tmp_path / "missing", out=tmp_path / "run", docker=docker)

    assert exc.value.cause == REPO_NOT_FOUND
    assert docker.calls == []
    assert fake.calls == []


def test_intake_failure_removes_the_network_and_writes_no_results(
    repo, tmp_path, monkeypatch
):
    docker = FakeDocker()
    fake = FakeIntake(_snapshot(), fail=IntakeError(BUILD_FAILED, "npm ERR!"))
    monkeypatch.setattr(scan, "intake", fake)

    with pytest.raises(IntakeError) as exc:
        scan.scan_local(repo, out=tmp_path / "run", docker=docker)

    assert exc.value.cause == BUILD_FAILED
    assert docker.networks == []
    assert docker.calls[-1][0] == "remove_network"
    assert not [call for call in docker.calls if call[0] == "start_sidecar"]
    assert not (tmp_path / "run" / "results.json").exists()


def test_a_probe_crash_removes_the_sidecar_and_network(
    repo, tmp_path, monkeypatch
):
    docker = FakeDocker()
    fake = FakeIntake(_snapshot())
    monkeypatch.setattr(scan, "intake", fake)
    monkeypatch.setattr(scan, "ProbeClient", ExplodingClient)

    with pytest.raises(RuntimeError):
        scan.scan_local(repo, out=tmp_path / "run", docker=docker)

    assert ("remove", SIDECAR) in docker.calls
    assert docker.sidecars == []
    assert docker.networks == []


def test_sidecar_cleanup_failure_does_not_mask_a_probe_crash(
    repo, tmp_path, monkeypatch
):
    docker = FakeDocker(fail_sidecar_remove=True)
    fake = FakeIntake(_snapshot())
    monkeypatch.setattr(scan, "intake", fake)
    monkeypatch.setattr(scan, "ProbeClient", ExplodingClient)

    with pytest.raises(RuntimeError):
        scan.scan_local(repo, out=tmp_path / "run", docker=docker)

    assert ("remove", SIDECAR) in docker.calls
    assert docker.networks == []


def test_network_cleanup_failure_does_not_mask_an_intake_failure(
    repo, tmp_path, monkeypatch
):
    docker = FakeDocker(fail_network_remove=True)
    fake = FakeIntake(_snapshot(), fail=IntakeError(BUILD_FAILED, "npm ERR!"))
    monkeypatch.setattr(scan, "intake", fake)

    with pytest.raises(IntakeError) as exc:
        scan.scan_local(repo, out=tmp_path / "run", docker=docker)

    assert exc.value.cause == BUILD_FAILED
    assert any(call[0] == "remove_network" for call in docker.calls)


def test_scan_runs_one_unauth_probe_per_declared_endpoint(
    repo, tmp_path, monkeypatch
):
    docker = FakeDocker(responses={"unauth": _payload("unauth", EXPOSED)})
    fake = FakeIntake(_snapshot())
    monkeypatch.setattr(scan, "intake", fake)

    outcome = scan.scan_local(
        repo,
        out=tmp_path / "run",
        docker=docker,
        endpoints=["/api/users", "/api/admin"],
    )

    exec_calls = [call for call in docker.calls if call[0] == "exec"]
    assert [call[2] for call in exec_calls] == [
        ["python", "/pry/sidecar.py", "cors", BASE],
        ["python", "/pry/sidecar.py", "errors", BASE],
        ["python", "/pry/sidecar.py", "secrets", BASE],
        ["python", "/pry/sidecar.py", "unauth", BASE, "/api/users"],
        ["python", "/pry/sidecar.py", "unauth", BASE, "/api/admin"],
    ]
    assert [result.probe for result in outcome.results] == [
        "cors",
        "errors",
        "secrets",
        "unauth",
        "unauth",
    ]
    assert [result.verdict for result in outcome.results] == [
        NOT_REPRODUCED,
        NOT_REPRODUCED,
        NOT_REPRODUCED,
        EXPOSED,
        EXPOSED,
    ]
    assert outcome.summary == {
        EXPOSED: 2,
        NOT_REPRODUCED: 3,
        UNVERIFIED: 0,
    }
    data = json.loads(outcome.results_path.read_text())
    assert [entry["probe"] for entry in data["results"]] == [
        "cors",
        "errors",
        "secrets",
        "unauth",
        "unauth",
    ]
    assert data["summary"] == {EXPOSED: 2, NOT_REPRODUCED: 3, UNVERIFIED: 0}
    assert docker.sidecars == []
    assert docker.networks == []


def test_scan_without_declared_endpoints_runs_exactly_three_probes(
    repo, tmp_path, monkeypatch
):
    docker = FakeDocker()
    fake = FakeIntake(_snapshot())
    monkeypatch.setattr(scan, "intake", fake)

    outcome = scan.scan_local(repo, out=tmp_path / "run", docker=docker)

    exec_calls = [call for call in docker.calls if call[0] == "exec"]
    assert len(exec_calls) == 3
    assert [result.probe for result in outcome.results] == [
        "cors",
        "errors",
        "secrets",
    ]


@pytest.mark.parametrize(
    "bad",
    [
        "http://evil.invalid",
        "https://evil.invalid/api",
        "//evil.invalid",
        "/api users",
        "api/users",
        "",
        "/" + "a" * 2048,
    ],
)
def test_scan_rejects_invalid_endpoints_before_touching_docker(
    repo, tmp_path, monkeypatch, bad
):
    docker = FakeDocker()
    fake = FakeIntake(_snapshot())
    monkeypatch.setattr(scan, "intake", fake)

    with pytest.raises(ProbeError) as exc:
        scan.scan_local(
            repo,
            out=tmp_path / "run",
            docker=docker,
            endpoints=["/api/users", bad],
        )

    assert exc.value.cause == INVALID_ENDPOINT
    assert docker.calls == []
    assert fake.calls == []
