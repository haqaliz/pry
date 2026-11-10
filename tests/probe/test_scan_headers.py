"""Local header-observation scan orchestration with a fake Docker (AT1, AT4, AT5).

Nothing here starts a container or touches the network.
"""

import json
from pathlib import Path

import pytest

import pry.probe.scan as scan
from pry.intake import IntakeResult, SandboxHandle
from pry.intake.docker import CommandResult
from pry.probe.headers import OBSERVED
from pry.probe.rate_limit import RateLimitConfig
from pry.probe.results import EXPOSED, NOT_REPRODUCED, UNVERIFIED

SANDBOX_ID = "pry-0123456789ab"
SIDECAR = "pry-probe-" + SANDBOX_ID
PORT = 8000
BASE = "http://app:%d" % PORT


class FakeDocker:
    """Records calls and scripts the floor and header responses."""

    def __init__(self, headers=None):
        self.headers = headers
        self.calls = []
        self.networks = []
        self.containers = []

    def create_network(self, name):
        self.calls.append(("create_network", name))
        self.networks.append(name)

    def remove_network(self, name):
        self.calls.append(("remove_network", name))
        if name in self.networks:
            self.networks.remove(name)

    def start_sidecar(self, network, name, script):
        self.calls.append(("start_sidecar", network, name, str(script)))
        self.containers.append(name)
        return "probe123"

    def remove(self, container):
        self.calls.append(("remove", container))
        if container in self.containers:
            self.containers.remove(container)

    def exec(self, container, command, timeout=10):
        self.calls.append(("exec", container, list(command), timeout))
        if command[2] == "headers":
            response = self.headers
            if response is None:
                response = _observation()
            if isinstance(response, Exception):
                raise response
            if isinstance(response, CommandResult):
                return response
            return CommandResult(
                0, json.dumps(response).encode("utf-8"), b"", False
            )
        if command[2] == "rate_limit":
            return CommandResult(
                0,
                json.dumps(_rate_observation()).encode("utf-8"),
                b"",
                False,
            )
        return CommandResult(
            0,
            json.dumps(_floor_payload(command[2])).encode("utf-8"),
            b"",
            False,
        )


class FakeIntake:
    def __init__(self, snapshot):
        self.snapshot = snapshot

    def __call__(self, path, **kwargs):
        run_dir = Path(kwargs["out"])
        run_dir.mkdir(parents=True, exist_ok=True)
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


def _snapshot():
    return {
        "version": 1,
        "sandbox_id": SANDBOX_ID,
        "created_at": "2026-11-11T00:00:00Z",
        "target": {
            "path": "/repo",
            "kind": "static",
            "git_commit": "a" * 40,
            "git_dirty": False,
            "tree_sha256": "b" * 64,
        },
        "project": {
            "image": "python:3.9-slim",
            "image_digest": "sha256:" + "c" * 64,
            "port": PORT,
        },
        "sandbox": {},
        "result": {},
    }


def _floor_payload(probe):
    return {
        "probe": probe,
        "verdict": NOT_REPRODUCED,
        "cause": None,
        "evidence": "%s checked" % probe,
        "request": {
            "method": "GET",
            "url": BASE + "/",
            "headers": {"User-Agent": "pry/0.1"},
        },
        "response": {"status": 200, "headers": {}, "body": "ok"},
    }


def _observation(status=OBSERVED):
    return {
        "probe": "headers",
        "status": status,
        "evidence": "6 recommended response headers checked on /: 1 present, "
        "5 missing (hardening observation)",
        "request": {
            "method": "GET",
            "url": BASE + "/",
            "headers": {"User-Agent": "pry/0.1"},
        },
        "response": {"status": 200, "headers": {}, "body": "ok"},
        "missing": ["content-security-policy"],
        "present": ["x-frame-options"],
    }


def _rate_observation():
    return {
        "probe": "rate_limit",
        "status": OBSERVED,
        "evidence": "1 requests accepted without throttling "
        "(hardening observation)",
        "request": {
            "method": "GET",
            "url": BASE + "/api/ping",
            "headers": {"User-Agent": "pry/0.1"},
        },
        "response": {"status": 200, "headers": {}, "body": "ok"},
        "count": 1,
        "statuses": [200],
    }


@pytest.fixture(autouse=True)
def proof_key(tmp_path, monkeypatch):
    monkeypatch.setenv("PRY_PROOF_KEY", str(tmp_path / "proof.key"))


@pytest.fixture
def repo(tmp_path):
    path = tmp_path / "repo"
    path.mkdir()
    return path


def _scan(repo, tmp_path, monkeypatch, docker, **kwargs):
    monkeypatch.setattr(scan, "intake", FakeIntake(_snapshot()))
    return scan.scan_local(repo, out=tmp_path / "run", docker=docker, **kwargs)


def _header_execs(docker):
    return [
        call
        for call in docker.calls
        if call[0] == "exec" and call[2][2] == "headers"
    ]


def test_scan_with_headers_appends_the_observation(repo, tmp_path, monkeypatch):
    docker = FakeDocker()

    outcome = _scan(repo, tmp_path, monkeypatch, docker, headers=True)

    assert _header_execs(docker) == [
        (
            "exec",
            SIDECAR,
            ["python", "/pry/sidecar.py", "headers", BASE],
            20,
        )
    ]
    assert [result.probe for result in outcome.results] == [
        "cors",
        "errors",
        "secrets",
        "database",
    ]
    assert outcome.summary == {
        EXPOSED: 0,
        NOT_REPRODUCED: 4,
        UNVERIFIED: 0,
    }
    assert [observation["probe"] for observation in outcome.observations] == [
        "headers"
    ]
    observation = outcome.observations[0]
    assert observation["status"] == OBSERVED
    assert observation["missing"] == ["content-security-policy"]
    assert observation["present"] == ["x-frame-options"]
    assert "proof" not in observation
    assert "verdict" not in observation
    assert not (tmp_path / "run" / "proofs").exists()


def test_results_json_includes_the_header_observation(
    repo, tmp_path, monkeypatch
):
    docker = FakeDocker()

    outcome = _scan(repo, tmp_path, monkeypatch, docker, headers=True)

    data = json.loads(outcome.results_path.read_text(encoding="utf-8"))
    assert len(data["observations"]) == 1
    stored = data["observations"][0]
    assert set(stored) == {
        "probe",
        "status",
        "evidence",
        "request",
        "response",
        "missing",
        "present",
    }
    assert stored["probe"] == "headers"
    assert stored["status"] == OBSERVED
    assert "verdict" not in stored
    assert "proof" not in stored
    assert data["summary"] == {
        EXPOSED: 0,
        NOT_REPRODUCED: 4,
        UNVERIFIED: 0,
    }


def test_without_headers_nothing_changes(repo, tmp_path, monkeypatch):
    docker = FakeDocker()

    outcome = _scan(repo, tmp_path, monkeypatch, docker)

    assert _header_execs(docker) == []
    assert outcome.observations == []
    data = json.loads(outcome.results_path.read_text(encoding="utf-8"))
    assert data["observations"] == []


def test_a_headers_exec_failure_is_unverified_and_the_scan_continues(
    repo, tmp_path, monkeypatch
):
    docker = FakeDocker(
        headers=CommandResult(1, b"", b"probe exploded", False)
    )

    outcome = _scan(repo, tmp_path, monkeypatch, docker, headers=True)

    observation = outcome.observations[0]
    assert observation["status"] == UNVERIFIED
    assert observation["response"] is None
    assert observation["missing"] == []
    assert observation["present"] == []
    assert "EXEC_FAILED" in observation["evidence"]
    assert "probe exploded" in observation["evidence"]
    assert [result.probe for result in outcome.results] == [
        "cors",
        "errors",
        "secrets",
        "database",
    ]
    assert outcome.results_path.exists()


def test_a_malformed_headers_payload_is_unverified(
    repo, tmp_path, monkeypatch
):
    docker = FakeDocker(headers={"unexpected": True})

    outcome = _scan(repo, tmp_path, monkeypatch, docker, headers=True)

    observation = outcome.observations[0]
    assert observation["status"] == UNVERIFIED
    assert "HEADERS_PROBE_INVALID" in observation["evidence"]
    assert outcome.results_path.exists()


def test_headers_and_rate_limit_observations_stay_separate(
    repo, tmp_path, monkeypatch
):
    docker = FakeDocker()
    config = RateLimitConfig(endpoint="/api/ping", count=1)

    outcome = _scan(
        repo,
        tmp_path,
        monkeypatch,
        docker,
        headers=True,
        rate_limit_config=config,
    )

    assert [observation["probe"] for observation in outcome.observations] == [
        "headers",
        "rate_limit",
    ]
    assert "proof" not in outcome.observations[0]
    data = json.loads(outcome.results_path.read_text(encoding="utf-8"))
    assert [entry["probe"] for entry in data["observations"]] == [
        "headers",
        "rate_limit",
    ]
