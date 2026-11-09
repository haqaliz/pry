"""Local SSRF scan orchestration with a fake Docker (AT1, AT2, AT8, AT9)."""

import json
import re
from pathlib import Path

import pytest

import pry.probe.scan as scan
from pry.intake import IntakeResult, SandboxHandle
from pry.intake.docker import CommandResult
from pry.intake.errors import START_FAILED, IntakeError
from pry.probe.results import EXPOSED, NOT_REPRODUCED, UNVERIFIED
from pry.probe.ssrf import (
    SSRF_APP_REQUEST_FAILED,
    SSRF_PROBE_FAILED,
    SSRF_PROBE_INVALID,
    SsrfConfig,
)
from pry.proof import load_bundle, verify_bundle

SANDBOX_ID = "pry-0123456789ab"
SIDECAR = "pry-probe-" + SANDBOX_ID
CALLBACK = "pry-callback-" + SANDBOX_ID
PORT = 8000
BASE = "http://app:%d" % PORT
CONFIG = SsrfConfig(endpoint="/api/fetch", parameter="url")
SECRET = "scan-cookie-secret"


class FakeDocker:
    """Records calls and scripts the floor probes plus the SSRF exec."""

    def __init__(
        self,
        ssrf_payload=None,
        fail_callback_start=None,
        ssrf_exec=None,
    ):
        self.ssrf_payload = ssrf_payload
        self.fail_callback_start = fail_callback_start
        self.ssrf_exec = ssrf_exec
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

    def start_callback_sidecar(self, network, name, source_dir):
        self.calls.append(
            ("start_callback_sidecar", network, name, str(source_dir))
        )
        if self.fail_callback_start is not None:
            raise self.fail_callback_start
        self.containers.append(name)
        return "callback123"

    def remove(self, container):
        self.calls.append(("remove", container))
        if container in self.containers:
            self.containers.remove(container)

    def exec(self, container, command, timeout=10):
        self.calls.append(("exec", container, list(command), timeout))
        if command[1] == "/pry/ssrf_probe.py":
            if isinstance(self.ssrf_exec, Exception):
                raise self.ssrf_exec
            if isinstance(self.ssrf_exec, CommandResult):
                return self.ssrf_exec
            payload = self.ssrf_payload
            if callable(payload):
                payload = payload(command[5])
            return CommandResult(
                0, json.dumps(payload or {}).encode("utf-8"), b"", False
            )
        probe = command[2]
        return CommandResult(
            0,
            json.dumps(_floor_payload(probe)).encode("utf-8"),
            b"",
            False,
        )


class FakeIntake:
    def __init__(self, snapshot):
        self.snapshot = snapshot
        self.calls = []

    def __call__(self, path, **kwargs):
        self.calls.append((path, kwargs))
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
        "created_at": "2026-11-10T00:00:00Z",
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


def _ssrf_payload(nonce, hit=True, cause=None, request_headers=None):
    return {
        "hit": hit,
        "cause": cause,
        "request": {
            "method": "GET",
            "url": BASE
            + CONFIG.endpoint
            + "?url=http%3A%2F%2Fpry-callback%3A9000%2F"
            + nonce,
            "headers": (
                {"User-Agent": "pry/0.1"}
                if request_headers is None
                else request_headers
            ),
        },
        "app_response": {
            "status": 200,
            "headers": {"Content-Type": "text/plain"},
            "body": "ok",
        },
        "callback_hit": {
            "method": "GET",
            "path": "/" + nonce,
            "headers": {"User-Agent": "python-urllib"},
        }
        if hit
        else None,
    }


@pytest.fixture(autouse=True)
def proof_key(tmp_path, monkeypatch):
    monkeypatch.setenv("PRY_PROOF_KEY", str(tmp_path / "proof.key"))


@pytest.fixture
def repo(tmp_path):
    path = tmp_path / "repo"
    path.mkdir()
    return path


def _scan(repo, tmp_path, monkeypatch, docker):
    monkeypatch.setattr(scan, "intake", FakeIntake(_snapshot()))
    return scan.scan_local(
        repo, out=tmp_path / "run", docker=docker, ssrf_config=CONFIG
    )


def _network(docker):
    return [call[1] for call in docker.calls if call[0] == "create_network"][0]


def _ssrf_exec(docker):
    return [
        call
        for call in docker.calls
        if call[0] == "exec" and call[2][1] == "/pry/ssrf_probe.py"
    ][0]


def test_ssrf_runs_after_the_floor_probes_and_appends_the_result(
    repo, tmp_path, monkeypatch
):
    docker = FakeDocker(ssrf_payload=_ssrf_payload)

    outcome = _scan(repo, tmp_path, monkeypatch, docker)

    network = _network(docker)
    started = [
        call for call in docker.calls if call[0] == "start_callback_sidecar"
    ]
    assert started == [
        (
            "start_callback_sidecar",
            network,
            CALLBACK,
            str(Path(scan.__file__).with_name("callback_server.py").parent),
        )
    ]
    execs = [call for call in docker.calls if call[0] == "exec"]
    floor_index = max(
        index for index, call in enumerate(execs) if call[2][1] != "/pry/ssrf_probe.py"
    )
    ssrf_index = min(
        index for index, call in enumerate(execs) if call[2][1] == "/pry/ssrf_probe.py"
    )
    assert ssrf_index > floor_index

    ssrf_call = _ssrf_exec(docker)
    command = ssrf_call[2]
    assert ssrf_call[1] == CALLBACK
    assert command[:5] == [
        "python",
        "/pry/ssrf_probe.py",
        BASE,
        CONFIG.endpoint,
        CONFIG.parameter,
    ]
    assert re.fullmatch(r"[0-9a-f]{32}", command[5])
    assert command[6] == "http://pry-callback:9000"
    assert len(command) == 7
    assert ssrf_call[3] == 30

    assert [result.probe for result in outcome.results] == [
        "cors",
        "errors",
        "secrets",
        "ssrf",
    ]
    result = outcome.results[-1]
    assert result.verdict == EXPOSED
    assert result.response["status"] == 200
    assert result.response["path"] == "/" + command[5]
    assert "/" + command[5] in result.evidence
    assert outcome.summary == {
        EXPOSED: 1,
        NOT_REPRODUCED: 3,
        UNVERIFIED: 0,
    }

    assert ("remove", CALLBACK) in docker.calls
    assert docker.containers == []
    assert docker.networks == []


def test_an_exposed_ssrf_result_is_signed_in_results_json(
    repo, tmp_path, monkeypatch
):
    docker = FakeDocker(ssrf_payload=_ssrf_payload)

    outcome = _scan(repo, tmp_path, monkeypatch, docker)

    result = outcome.results[-1]
    assert result.proof
    payload, _fingerprint = verify_bundle(load_bundle(result.proof))
    assert payload["finding"]["probe"] == "ssrf"
    assert payload["finding"]["verdict"] == EXPOSED
    assert payload["finding"]["request"] == result.request
    assert payload["finding"]["response"] == result.response

    data = json.loads(outcome.results_path.read_text(encoding="utf-8"))
    assert data["results"][-1]["probe"] == "ssrf"
    assert data["results"][-1]["proof"] == result.proof


def test_without_an_ssrf_config_no_callback_sidecar_starts(
    repo, tmp_path, monkeypatch
):
    docker = FakeDocker()
    docker.start_callback_sidecar = lambda *args: pytest.fail(
        "callback sidecar must not start without a config"
    )
    monkeypatch.setattr(scan, "intake", FakeIntake(_snapshot()))

    outcome = scan.scan_local(repo, out=tmp_path / "run", docker=docker)

    assert [result.probe for result in outcome.results] == [
        "cors",
        "errors",
        "secrets",
    ]
    assert not [
        call for call in docker.calls if call[0] == "start_callback_sidecar"
    ]
    assert not [
        call
        for call in docker.calls
        if call[0] == "exec" and call[2][1] == "/pry/ssrf_probe.py"
    ]
    assert docker.networks == []


def test_an_app_request_failure_is_unverified_and_the_scan_continues(
    repo, tmp_path, monkeypatch
):
    docker = FakeDocker(
        ssrf_payload=lambda nonce: _ssrf_payload(
            nonce, hit=False, cause=SSRF_APP_REQUEST_FAILED
        )
    )

    outcome = _scan(repo, tmp_path, monkeypatch, docker)

    assert [result.probe for result in outcome.results] == [
        "cors",
        "errors",
        "secrets",
        "ssrf",
    ]
    assert outcome.results[-1].verdict == UNVERIFIED
    assert outcome.results[-1].cause == SSRF_APP_REQUEST_FAILED
    assert outcome.results_path.exists()
    assert ("remove", CALLBACK) in docker.calls
    assert docker.containers == []
    assert docker.networks == []


def test_a_callback_start_failure_is_unverified_and_cleaned_up(
    repo, tmp_path, monkeypatch
):
    docker = FakeDocker(
        fail_callback_start=IntakeError(START_FAILED, "cannot start callback")
    )

    outcome = _scan(repo, tmp_path, monkeypatch, docker)

    result = outcome.results[-1]
    assert result.probe == "ssrf"
    assert result.verdict == UNVERIFIED
    assert result.cause == SSRF_PROBE_FAILED
    assert "cannot start callback" in result.evidence
    assert not [
        call
        for call in docker.calls
        if call[0] == "exec" and call[2][1] == "/pry/ssrf_probe.py"
    ]
    assert ("remove", CALLBACK) in docker.calls
    assert docker.networks == []
    assert outcome.results_path.exists()


@pytest.mark.parametrize(
    "ssrf_exec",
    [
        CommandResult(1, b"", b"probe exploded", False),
        CommandResult(-1, b"", b"", True),
        RuntimeError("docker exec failed"),
    ],
)
def test_a_probe_exec_failure_is_unverified_and_the_scan_continues(
    repo, tmp_path, monkeypatch, ssrf_exec
):
    docker = FakeDocker(ssrf_exec=ssrf_exec)

    outcome = _scan(repo, tmp_path, monkeypatch, docker)

    result = outcome.results[-1]
    assert result.probe == "ssrf"
    assert result.verdict == UNVERIFIED
    assert result.cause == SSRF_PROBE_FAILED
    assert ("remove", CALLBACK) in docker.calls
    assert docker.containers == []
    assert docker.networks == []
    assert outcome.results_path.exists()


def test_malformed_probe_json_is_unverified_and_cleaned_up(
    repo, tmp_path, monkeypatch
):
    docker = FakeDocker(ssrf_exec=CommandResult(0, b"not json", b"", False))

    outcome = _scan(repo, tmp_path, monkeypatch, docker)

    result = outcome.results[-1]
    assert result.verdict == UNVERIFIED
    assert result.cause == SSRF_PROBE_INVALID
    assert ("remove", CALLBACK) in docker.calls
    assert docker.containers == []
    assert docker.networks == []


def test_ssrf_result_headers_are_redacted_in_results_json(
    repo, tmp_path, monkeypatch
):
    docker = FakeDocker(
        ssrf_payload=lambda nonce: _ssrf_payload(
            nonce, request_headers={"Cookie": SECRET, "User-Agent": "pry/0.1"}
        )
    )

    outcome = _scan(repo, tmp_path, monkeypatch, docker)

    stored = outcome.results_path.read_text(encoding="utf-8")
    assert SECRET not in stored
    assert "[redacted]" in stored
