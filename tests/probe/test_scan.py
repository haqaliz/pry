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
from pry.probe.idor import IdorConfig
from pry.probe.rate_limit import RateLimitConfig
from pry.probe.scan import INVALID_ENDPOINT, ScanOutcome
from pry.probe.ssrf import SsrfConfig
from pry.proof import (
    PROOF_FAILED,
    ProofError,
    load_bundle,
    verify_bundle,
)
from pry.report.corpus import REPORT_FAILED, ReportError, read_findings

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
        self.config_paths = []
        self.config_modes = []
        self.config_payloads = []

    def create_network(self, name):
        self.calls.append(("create_network", name))
        self.networks.append(name)

    def remove_network(self, name):
        self.calls.append(("remove_network", name))
        if self.fail_network_remove:
            raise IntakeError(SANDBOX_ERROR, "network remove failed")
        if name in self.networks:
            self.networks.remove(name)

    def start_sidecar(self, network, name, script, config_path=None):
        call = ("start_sidecar", network, name, str(script))
        if config_path is not None:
            call = call + (str(config_path),)
            self.config_paths.append(str(config_path))
            self.config_modes.append(
                stat.S_IMODE(Path(config_path).stat().st_mode)
            )
            self.config_payloads.append(
                json.loads(Path(config_path).read_text(encoding="utf-8"))
            )
        self.calls.append(call)
        self.sidecars.append(name)
        return "sidecar123"

    def start_callback_sidecar(self, network, name, source_dir):
        self.calls.append(
            ("start_callback_sidecar", network, name, str(source_dir))
        )
        self.sidecars.append(name)
        return "callback123"

    def remove(self, container):
        self.calls.append(("remove", container))
        if self.fail_sidecar_remove:
            raise IntakeError(SANDBOX_ERROR, "container remove failed")
        if container in self.sidecars:
            self.sidecars.remove(container)

    def exec(self, container, command, timeout=10):
        self.calls.append(("exec", container, list(command), timeout))
        if command[1] == "/pry/ssrf_probe.py":
            payload = self.responses.get("ssrf") or {}
            return CommandResult(
                0, json.dumps(payload).encode("utf-8"), b"", False
            )
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
        "target": {
            "path": path,
            "kind": kind,
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


@pytest.fixture(autouse=True)
def proof_key(tmp_path, monkeypatch):
    path = tmp_path / "proof.key"
    monkeypatch.setenv("PRY_PROOF_KEY", str(path))
    return path


@pytest.fixture(autouse=True)
def corpus_file(tmp_path, monkeypatch):
    path = tmp_path / "corpus.jsonl"
    monkeypatch.setenv("PRY_CORPUS", str(path))
    return path


def _proof_files(run_dir):
    return sorted((Path(run_dir) / "proofs").glob("*.json"))


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
        ["python", "/pry/sidecar.py", "database", BASE],
    ]
    assert all(call[1] == SIDECAR for call in exec_calls)
    assert all(call[3] == 20 for call in exec_calls)
    assert ("remove", SIDECAR) in docker.calls
    assert docker.sidecars == []
    assert [result.probe for result in outcome.results] == [
        "cors",
        "errors",
        "secrets",
        "database",
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
        "database",
    ]
    assert all(isinstance(result, ProbeResult) for result in outcome.results)
    assert outcome.summary == {EXPOSED: 1, NOT_REPRODUCED: 2, UNVERIFIED: 1}
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
    assert set(data) == {
        "version",
        "target",
        "results",
        "summary",
        "observations",
        "created_at",
    }
    assert data["observations"] == []
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
        "database",
    ]
    assert data["summary"] == {EXPOSED: 2, NOT_REPRODUCED: 2, UNVERIFIED: 0}
    assert data["created_at"].endswith("Z")
    for entry in data["results"]:
        assert set(entry) == {
            "probe",
            "verdict",
            "cause",
            "evidence",
            "request",
            "response",
            "proof",
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
        NOT_REPRODUCED,
    ]
    assert outcome.results[1].cause == "EXEC_FAILED"
    assert outcome.summary == {EXPOSED: 1, NOT_REPRODUCED: 2, UNVERIFIED: 1}
    assert outcome.results_path.exists()
    assert [call[2][2] for call in docker.calls if call[0] == "exec"] == [
        "cors",
        "errors",
        "secrets",
        "database",
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
        ["python", "/pry/sidecar.py", "database", BASE],
        ["python", "/pry/sidecar.py", "unauth", BASE, "/api/users"],
        ["python", "/pry/sidecar.py", "unauth", BASE, "/api/admin"],
    ]
    assert [result.probe for result in outcome.results] == [
        "cors",
        "errors",
        "secrets",
        "database",
        "unauth",
        "unauth",
    ]
    assert [result.verdict for result in outcome.results] == [
        NOT_REPRODUCED,
        NOT_REPRODUCED,
        NOT_REPRODUCED,
        NOT_REPRODUCED,
        EXPOSED,
        EXPOSED,
    ]
    assert outcome.summary == {
        EXPOSED: 2,
        NOT_REPRODUCED: 4,
        UNVERIFIED: 0,
    }
    data = json.loads(outcome.results_path.read_text())
    assert [entry["probe"] for entry in data["results"]] == [
        "cors",
        "errors",
        "secrets",
        "database",
        "unauth",
        "unauth",
    ]
    assert data["summary"] == {EXPOSED: 2, NOT_REPRODUCED: 4, UNVERIFIED: 0}
    assert docker.sidecars == []
    assert docker.networks == []


def test_scan_without_declared_endpoints_runs_exactly_the_floor_probes(
    repo, tmp_path, monkeypatch
):
    docker = FakeDocker()
    fake = FakeIntake(_snapshot())
    monkeypatch.setattr(scan, "intake", fake)

    outcome = scan.scan_local(repo, out=tmp_path / "run", docker=docker)

    exec_calls = [call for call in docker.calls if call[0] == "exec"]
    assert len(exec_calls) == 4
    assert [result.probe for result in outcome.results] == [
        "cors",
        "errors",
        "secrets",
        "database",
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


EXPECTED_TARGET = {
    "sandbox_id": SANDBOX_ID,
    "path": "/repo",
    "kind": "static",
    "git_commit": "a" * 40,
    "git_dirty": False,
    "tree_sha256": "b" * 64,
    "image": "python:3.9-slim",
    "image_digest": "sha256:" + "c" * 64,
    "port": PORT,
}


def _scan_with_verdicts(repo, tmp_path, monkeypatch, verdicts):
    docker = FakeDocker(
        responses={
            probe: _payload(probe, verdict)
            for probe, verdict in verdicts.items()
        }
    )
    monkeypatch.setattr(scan, "intake", FakeIntake(_snapshot()))
    return scan.scan_local(repo, out=tmp_path / "run", docker=docker), docker


def test_scan_writes_one_signed_bundle_per_exposed_finding(
    repo, tmp_path, monkeypatch
):
    outcome, _ = _scan_with_verdicts(
        repo,
        tmp_path,
        monkeypatch,
        {"cors": EXPOSED, "errors": NOT_REPRODUCED, "secrets": EXPOSED},
    )

    proofs = _proof_files(tmp_path / "run")
    assert len(proofs) == 2
    exposed = [result for result in outcome.results if result.verdict == EXPOSED]
    assert len(exposed) == 2
    assert all(result.proof for result in exposed)
    assert all(
        result.proof is None
        for result in outcome.results
        if result.verdict != EXPOSED
    )

    fingerprints = set()
    for result in exposed:
        bundle = load_bundle(result.proof)
        payload, fingerprint = verify_bundle(bundle)
        assert payload["target"] == EXPECTED_TARGET
        assert payload["finding"] == {
            "probe": result.probe,
            "verdict": EXPOSED,
            "cause": result.cause,
            "evidence": result.evidence,
            "request": result.request,
            "response": result.response,
        }
        assert stat.S_IMODE(Path(result.proof).stat().st_mode) == 0o600
        fingerprints.add(fingerprint)
    assert len(fingerprints) == 1


def test_scan_results_json_includes_proof_paths(repo, tmp_path, monkeypatch):
    outcome, _ = _scan_with_verdicts(
        repo,
        tmp_path,
        monkeypatch,
        {"cors": EXPOSED, "errors": NOT_REPRODUCED, "secrets": EXPOSED},
    )

    data = json.loads(outcome.results_path.read_text())
    proofs = [entry["proof"] for entry in data["results"]]
    assert proofs[0] is not None
    assert proofs[1] is None
    assert proofs[2] is not None
    assert proofs[0] != proofs[2]
    for proof in (proofs[0], proofs[2]):
        assert Path(proof).is_file()
        payload, _ = verify_bundle(load_bundle(proof))
        assert payload["finding"]["verdict"] == EXPOSED


def test_scan_writes_no_bundle_without_exposed_findings(
    repo, tmp_path, monkeypatch, proof_key
):
    outcome, _ = _scan_with_verdicts(
        repo,
        tmp_path,
        monkeypatch,
        {"cors": NOT_REPRODUCED, "errors": UNVERIFIED, "secrets": NOT_REPRODUCED},
    )

    assert [result.proof for result in outcome.results] == [None] * 4
    assert not (tmp_path / "run" / "proofs").exists()
    assert not proof_key.exists()


def test_signing_failure_is_proof_failed_and_writes_no_results(
    repo, tmp_path, monkeypatch, proof_key
):
    proof_key.write_bytes(b"short")
    docker = FakeDocker(responses={"cors": _payload("cors", EXPOSED)})
    monkeypatch.setattr(scan, "intake", FakeIntake(_snapshot()))

    with pytest.raises(ProofError) as exc:
        scan.scan_local(repo, out=tmp_path / "run", docker=docker)

    assert exc.value.cause == PROOF_FAILED
    assert "PROOF_KEY_INVALID" in exc.value.message
    assert not (tmp_path / "run" / "results.json").exists()
    assert not (tmp_path / "run" / "proofs").exists()
    assert docker.sidecars == []
    assert docker.networks == []
    assert proof_key.read_bytes() == b"short"


def test_scan_appends_one_corpus_record_per_finding(
    repo, tmp_path, monkeypatch, corpus_file
):
    outcome, _ = _scan_with_verdicts(
        repo,
        tmp_path,
        monkeypatch,
        {"cors": EXPOSED, "errors": NOT_REPRODUCED, "secrets": EXPOSED},
    )

    records = read_findings()

    assert outcome.corpus_error is None
    assert [record["probe"] for record in records] == [
        "cors",
        "errors",
        "secrets",
        "database",
    ]
    assert [record["verdict"] for record in records] == [
        EXPOSED,
        NOT_REPRODUCED,
        EXPOSED,
        NOT_REPRODUCED,
    ]
    for record in records:
        assert set(record) == {
            "created_at",
            "sandbox_id",
            "target",
            "kind",
            "probe",
            "verdict",
            "cause",
            "proof",
            "fingerprint",
        }
        assert record["sandbox_id"] == SANDBOX_ID
        assert record["target"] == "/repo"
        assert record["kind"] == "static"
        assert record["created_at"].endswith("Z")
    exposed = [record for record in records if record["verdict"] == EXPOSED]
    assert all(Path(record["proof"]).is_file() for record in exposed)
    fingerprints = set()
    for record in exposed:
        payload, fingerprint = verify_bundle(load_bundle(record["proof"]))
        assert payload["finding"]["verdict"] == EXPOSED
        assert record["fingerprint"] == fingerprint
        fingerprints.add(fingerprint)
    assert len(fingerprints) == 1
    assert all(
        record["proof"] is None and record["fingerprint"] is None
        for record in records
        if record["verdict"] != EXPOSED
    )
    assert stat.S_IMODE(corpus_file.stat().st_mode) == 0o600


def test_a_corpus_failure_warns_without_failing_the_scan(
    repo, tmp_path, monkeypatch
):
    def fail(records):
        raise ReportError(REPORT_FAILED, "cannot append corpus: denied")

    monkeypatch.setattr(scan, "append_findings", fail)

    outcome, _ = _scan_with_verdicts(
        repo,
        tmp_path,
        monkeypatch,
        {"cors": EXPOSED, "errors": NOT_REPRODUCED, "secrets": NOT_REPRODUCED},
    )

    assert outcome.corpus_error == (
        "REPORT_FAILED: cannot append corpus: denied"
    )
    assert outcome.results_path.exists()
    assert len(outcome.results) == 4
    assert outcome.summary == {
        EXPOSED: 1,
        NOT_REPRODUCED: 3,
        UNVERIFIED: 0,
    }


IDOR_SECRET_A = "scan-alice-session"
IDOR_SECRET_B = "scan-bob-session"
IDOR = IdorConfig(
    headers_a={"Cookie": "sid=" + IDOR_SECRET_A},
    headers_b={"Cookie": "sid=" + IDOR_SECRET_B},
    object_a="/api/orders/1",
    object_b="/api/orders/2",
)
SSRF_CONFIG = SsrfConfig(endpoint="/api/fetch", parameter="url")
RATE_LIMIT_CONFIG = RateLimitConfig(endpoint="/api/ping", count=3)


def _run_texts(outcome):
    texts = [outcome.results_path.read_text(encoding="utf-8")]
    texts.extend(
        Path(proof).read_text(encoding="utf-8")
        for proof in _proof_files(outcome.results_path.parent)
    )
    return texts


def _assert_no_idor_leak(outcome, docker):
    temp_path = docker.config_paths[0]
    for text in _run_texts(outcome):
        assert IDOR_SECRET_A not in text
        assert IDOR_SECRET_B not in text
        assert temp_path not in text


def test_scan_mounts_a_0600_temp_copy_of_the_idor_config(
    repo, tmp_path, monkeypatch
):
    docker = FakeDocker(responses={"idor": _payload("idor", NOT_REPRODUCED)})
    monkeypatch.setattr(scan, "intake", FakeIntake(_snapshot()))

    outcome = scan.scan_local(
        repo, out=tmp_path / "run", docker=docker, idor_config=IDOR
    )

    started = [call for call in docker.calls if call[0] == "start_sidecar"]
    assert len(docker.config_paths) == 1
    assert started[0][-1] == docker.config_paths[0]
    assert docker.config_modes == [0o600]
    assert docker.config_payloads == [
        {
            "identity_a": {"headers": IDOR.headers_a},
            "identity_b": {"headers": IDOR.headers_b},
            "object_a": IDOR.object_a,
            "object_b": IDOR.object_b,
        }
    ]
    exec_calls = [call for call in docker.calls if call[0] == "exec"]
    assert exec_calls[-1][2] == [
        "python",
        "/pry/sidecar.py",
        "idor",
        BASE,
        "/pry-config/idor.json",
    ]
    assert outcome.results[-1].probe == "idor"
    assert outcome.summary == {
        EXPOSED: 0,
        NOT_REPRODUCED: 5,
        UNVERIFIED: 0,
    }
    assert not Path(docker.config_paths[0]).exists()
    _assert_no_idor_leak(outcome, docker)


def test_scan_runs_idor_after_floor_unauth_ssrf_and_rate_limit(
    repo, tmp_path, monkeypatch
):
    docker = FakeDocker(
        responses={
            "idor": _payload("idor", NOT_REPRODUCED),
            "ssrf": {
                "hit": True,
                "cause": None,
                "request": {
                    "method": "GET",
                    "url": BASE + "/api/fetch?url=http%3A%2F%2Fpry-callback%3A9000%2Fn",
                    "headers": {"User-Agent": "pry/0.1"},
                },
                "app_response": {"status": 200, "headers": {}, "body": "ok"},
                "callback_hit": {
                    "method": "GET",
                    "path": "/n",
                    "headers": {"User-Agent": "python-urllib"},
                },
            },
        }
    )
    monkeypatch.setattr(scan, "intake", FakeIntake(_snapshot()))

    outcome = scan.scan_local(
        repo,
        out=tmp_path / "run",
        docker=docker,
        endpoints=["/api/users"],
        ssrf_config=SSRF_CONFIG,
        rate_limit_config=RATE_LIMIT_CONFIG,
        idor_config=IDOR,
    )

    kinds = [
        "ssrf" if call[2][1] == "/pry/ssrf_probe.py" else call[2][2]
        for call in docker.calls
        if call[0] == "exec"
    ]
    assert kinds == [
        "cors",
        "errors",
        "secrets",
        "database",
        "unauth",
        "ssrf",
        "rate_limit",
        "idor",
    ]
    assert [result.probe for result in outcome.results] == [
        "cors",
        "errors",
        "secrets",
        "database",
        "unauth",
        "ssrf",
        "idor",
    ]
    assert [observation["probe"] for observation in outcome.observations] == [
        "rate_limit"
    ]


def test_scan_signs_an_exposed_idor_result_without_leaking_credentials(
    repo, tmp_path, monkeypatch
):
    docker = FakeDocker(responses={"idor": _payload("idor", EXPOSED)})
    monkeypatch.setattr(scan, "intake", FakeIntake(_snapshot()))

    outcome = scan.scan_local(
        repo, out=tmp_path / "run", docker=docker, idor_config=IDOR
    )

    idor = outcome.results[-1]
    assert idor.probe == "idor"
    assert idor.verdict == EXPOSED
    assert idor.proof is not None
    payload, _fingerprint = verify_bundle(load_bundle(idor.proof))
    assert payload["finding"]["probe"] == "idor"
    assert payload["finding"]["verdict"] == EXPOSED
    assert outcome.summary[EXPOSED] == 1
    assert not Path(docker.config_paths[0]).exists()
    _assert_no_idor_leak(outcome, docker)


def test_scan_removes_the_idor_temp_config_after_a_probe_failure(
    repo, tmp_path, monkeypatch
):
    docker = FakeDocker()
    monkeypatch.setattr(scan, "intake", FakeIntake(_snapshot()))
    monkeypatch.setattr(scan, "ProbeClient", ExplodingClient)

    with pytest.raises(RuntimeError):
        scan.scan_local(
            repo, out=tmp_path / "run", docker=docker, idor_config=IDOR
        )

    assert len(docker.config_paths) == 1
    assert not Path(docker.config_paths[0]).exists()
    assert docker.networks == []


class InterruptingClient:
    def __init__(self, docker, sidecar, base_url):
        pass

    def run_all(self):
        raise KeyboardInterrupt


def test_scan_removes_the_idor_temp_config_after_an_interrupt(
    repo, tmp_path, monkeypatch
):
    docker = FakeDocker()
    monkeypatch.setattr(scan, "intake", FakeIntake(_snapshot()))
    monkeypatch.setattr(scan, "ProbeClient", InterruptingClient)

    with pytest.raises(KeyboardInterrupt):
        scan.scan_local(
            repo, out=tmp_path / "run", docker=docker, idor_config=IDOR
        )

    assert len(docker.config_paths) == 1
    assert not Path(docker.config_paths[0]).exists()
    assert docker.networks == []


def test_scan_without_an_idor_config_mounts_nothing_and_runs_no_idor(
    repo, tmp_path, monkeypatch
):
    docker = FakeDocker()
    monkeypatch.setattr(scan, "intake", FakeIntake(_snapshot()))

    outcome = scan.scan_local(repo, out=tmp_path / "run", docker=docker)

    started = [call for call in docker.calls if call[0] == "start_sidecar"]
    assert docker.config_paths == []
    assert not any("/pry-config" in str(call) for call in started)
    exec_calls = [call for call in docker.calls if call[0] == "exec"]
    assert [call[2] for call in exec_calls] == [
        ["python", "/pry/sidecar.py", "cors", BASE],
        ["python", "/pry/sidecar.py", "errors", BASE],
        ["python", "/pry/sidecar.py", "secrets", BASE],
        ["python", "/pry/sidecar.py", "database", BASE],
    ]
    assert [result.probe for result in outcome.results] == [
        "cors",
        "errors",
        "secrets",
        "database",
    ]
