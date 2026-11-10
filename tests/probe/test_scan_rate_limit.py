"""Local rate-limit scan orchestration with a fake Docker (AT1-AT3, AT6).

Nothing here starts a container or touches the network.
"""

import json
from pathlib import Path

import pytest

import pry.probe.scan as scan
from pry.intake import IntakeResult, SandboxHandle
from pry.intake.docker import CommandResult
from pry.probe.rate_limit import OBSERVED, THROTTLED, RateLimitConfig
from pry.probe.results import EXPOSED, NOT_REPRODUCED, UNVERIFIED
from pry.probe.ssrf import SsrfConfig
from pry.proof import load_bundle, verify_bundle

SANDBOX_ID = "pry-0123456789ab"
SIDECAR = "pry-probe-" + SANDBOX_ID
CALLBACK = "pry-callback-" + SANDBOX_ID
PORT = 8000
BASE = "http://app:%d" % PORT
CONFIG = RateLimitConfig(endpoint="/api/ping", count=10)
SSRF_CONFIG = SsrfConfig(endpoint="/api/fetch", parameter="url")


class FakeDocker:
    """Records calls and scripts the floor, SSRF, and rate-limit responses."""

    def __init__(self, rate_limit=None, ssrf_payload=None):
        self.rate_limit = rate_limit
        self.ssrf_payload = ssrf_payload
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
        self.containers.append(name)
        return "callback123"

    def remove(self, container):
        self.calls.append(("remove", container))
        if container in self.containers:
            self.containers.remove(container)

    def exec(self, container, command, timeout=10):
        self.calls.append(("exec", container, list(command), timeout))
        if command[1] == "/pry/ssrf_probe.py":
            payload = self.ssrf_payload
            if callable(payload):
                payload = payload(command[5])
            return CommandResult(
                0, json.dumps(payload or {}).encode("utf-8"), b"", False
            )
        if command[2] == "rate_limit":
            response = self.rate_limit
            if response is None:
                response = _observation()
            if isinstance(response, Exception):
                raise response
            if isinstance(response, CommandResult):
                return response
            if callable(response):
                response = response(command[4], command[5])
            return CommandResult(
                0, json.dumps(response).encode("utf-8"), b"", False
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


def _observation(status=OBSERVED, count=10, statuses=None, evidence=None):
    return {
        "probe": "rate_limit",
        "status": status,
        "evidence": evidence
        or "10 requests accepted without throttling (hardening observation)",
        "request": {
            "method": "GET",
            "url": BASE + CONFIG.endpoint,
            "headers": {"User-Agent": "pry/0.1"},
        },
        "response": {"status": 200, "headers": {}, "body": "ok"},
        "count": count,
        "statuses": statuses if statuses is not None else [200] * count,
    }


def _ssrf_payload(nonce):
    return {
        "hit": True,
        "cause": None,
        "request": {
            "method": "GET",
            "url": BASE + SSRF_CONFIG.endpoint + "?url=http%3A%2F%2Fcallback",
            "headers": {"User-Agent": "pry/0.1"},
        },
        "app_response": {"status": 200, "headers": {}, "body": "ok"},
        "callback_hit": {
            "method": "GET",
            "path": "/" + nonce,
            "headers": {"User-Agent": "python-urllib"},
        },
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


def _rate_execs(docker):
    return [
        call
        for call in docker.calls
        if call[0] == "exec" and call[2][2] == "rate_limit"
    ]


def test_scan_appends_the_observation_after_the_floor_checks(
    repo, tmp_path, monkeypatch
):
    docker = FakeDocker()

    outcome = _scan(
        repo, tmp_path, monkeypatch, docker, rate_limit_config=CONFIG
    )

    execs = _rate_execs(docker)
    assert execs == [
        (
            "exec",
            SIDECAR,
            [
                "python",
                "/pry/sidecar.py",
                "rate_limit",
                BASE,
                CONFIG.endpoint,
                "10",
            ],
            120,
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
    assert len(outcome.observations) == 1
    observation = outcome.observations[0]
    assert observation["probe"] == "rate_limit"
    assert observation["status"] == OBSERVED
    assert observation["count"] == 10
    assert observation["statuses"] == [200] * 10
    assert observation["request"]["headers"] == {"user-agent": "pry/0.1"}
    assert "proof" not in observation
    assert "verdict" not in observation
    assert not (tmp_path / "run" / "proofs").exists()


def test_scan_records_a_throttled_observation(repo, tmp_path, monkeypatch):
    docker = FakeDocker(
        rate_limit=_observation(
            status=THROTTLED,
            count=4,
            statuses=[200, 200, 200, 429],
            evidence="throttled at request 4/10: status 429",
        )
    )

    outcome = _scan(
        repo, tmp_path, monkeypatch, docker, rate_limit_config=CONFIG
    )

    observation = outcome.observations[0]
    assert observation["status"] == THROTTLED
    assert observation["count"] == 4
    assert observation["statuses"] == [200, 200, 200, 429]
    assert "request 4/10" in observation["evidence"]
    assert outcome.summary == {
        EXPOSED: 0,
        NOT_REPRODUCED: 4,
        UNVERIFIED: 0,
    }


def test_results_json_includes_observations_beside_results(
    repo, tmp_path, monkeypatch
):
    docker = FakeDocker()

    outcome = _scan(
        repo, tmp_path, monkeypatch, docker, rate_limit_config=CONFIG
    )

    data = json.loads(outcome.results_path.read_text(encoding="utf-8"))
    assert set(data) == {
        "version",
        "target",
        "results",
        "summary",
        "observations",
        "created_at",
    }
    assert len(data["observations"]) == 1
    stored = data["observations"][0]
    assert stored["probe"] == "rate_limit"
    assert stored["status"] == OBSERVED
    assert set(stored) == {
        "probe",
        "status",
        "evidence",
        "request",
        "response",
        "count",
        "statuses",
    }
    assert "verdict" not in stored
    assert "proof" not in stored
    assert data["summary"] == {
        EXPOSED: 0,
        NOT_REPRODUCED: 4,
        UNVERIFIED: 0,
    }


def test_without_a_config_no_rate_limit_probe_runs(
    repo, tmp_path, monkeypatch
):
    docker = FakeDocker()

    outcome = _scan(repo, tmp_path, monkeypatch, docker)

    assert outcome.observations == []
    assert _rate_execs(docker) == []
    data = json.loads(outcome.results_path.read_text(encoding="utf-8"))
    assert data["observations"] == []


def test_a_rate_limit_exec_failure_is_unverified_and_the_scan_continues(
    repo, tmp_path, monkeypatch
):
    docker = FakeDocker(
        rate_limit=CommandResult(1, b"", b"probe exploded", False)
    )

    outcome = _scan(
        repo, tmp_path, monkeypatch, docker, rate_limit_config=CONFIG
    )

    observation = outcome.observations[0]
    assert observation["status"] == UNVERIFIED
    assert observation["count"] == 0
    assert observation["statuses"] == []
    assert observation["response"] is None
    assert "EXEC_FAILED" in observation["evidence"]
    assert "probe exploded" in observation["evidence"]
    assert [result.probe for result in outcome.results] == [
        "cors",
        "errors",
        "secrets",
        "database",
    ]
    assert outcome.results_path.exists()


def test_a_malformed_rate_limit_payload_is_unverified(
    repo, tmp_path, monkeypatch
):
    docker = FakeDocker(rate_limit={"unexpected": True})

    outcome = _scan(
        repo, tmp_path, monkeypatch, docker, rate_limit_config=CONFIG
    )

    observation = outcome.observations[0]
    assert observation["status"] == UNVERIFIED
    assert "RATE_LIMIT_PROBE_INVALID" in observation["evidence"]
    assert outcome.results_path.exists()


def test_ssrf_and_rate_limit_both_run_and_stay_separate(
    repo, tmp_path, monkeypatch
):
    docker = FakeDocker(
        rate_limit=_observation(), ssrf_payload=_ssrf_payload
    )

    outcome = _scan(
        repo,
        tmp_path,
        monkeypatch,
        docker,
        ssrf_config=SSRF_CONFIG,
        rate_limit_config=CONFIG,
    )

    execs = [call for call in docker.calls if call[0] == "exec"]
    ssrf_index = min(
        index
        for index, call in enumerate(execs)
        if call[2][1] == "/pry/ssrf_probe.py"
    )
    rate_index = min(
        index
        for index, call in enumerate(execs)
        if call[2][2] == "rate_limit"
    )
    assert ssrf_index < rate_index
    assert [result.probe for result in outcome.results] == [
        "cors",
        "errors",
        "secrets",
        "database",
        "ssrf",
    ]
    assert outcome.results[-1].verdict == EXPOSED
    assert outcome.results[-1].proof
    assert [observation["probe"] for observation in outcome.observations] == [
        "rate_limit"
    ]
    assert "proof" not in outcome.observations[0]
    payload, _fingerprint = verify_bundle(load_bundle(outcome.results[-1].proof))
    assert payload["finding"]["probe"] == "ssrf"
    data = json.loads(outcome.results_path.read_text(encoding="utf-8"))
    assert [entry["probe"] for entry in data["results"]][-1] == "ssrf"
    assert data["observations"][0]["status"] == OBSERVED
