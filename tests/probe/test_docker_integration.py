"""Opt-in Docker integration for the P3 read-only probes.

Run with: PRY_DOCKER_TESTS=1 uv run pytest -q -m docker
Local fixtures only; never a third-party target.
"""

import os
import shutil
from pathlib import Path

import pytest

from pry.intake.docker import DockerRunner
from pry.intake.project import tree_sha256
from pry.probe.results import EXPOSED, NOT_REPRODUCED
from pry.probe.scan import scan_local, sidecar_script_path
from pry.proof import load_bundle, verify_bundle

pytestmark = [
    pytest.mark.docker,
    pytest.mark.skipif(
        os.environ.get("PRY_DOCKER_TESTS") != "1",
        reason="set PRY_DOCKER_TESTS=1 to run Docker integration tests",
    ),
]

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"


@pytest.fixture(autouse=True)
def proof_key(tmp_path, monkeypatch):
    monkeypatch.setenv("PRY_PROOF_KEY", str(tmp_path / "proof.key"))


def test_vulnerable_fixture_reports_four_exposed(tmp_path):
    fixture = FIXTURES / "vulnerable-app"
    before = tree_sha256(fixture)

    outcome = scan_local(str(fixture), out=tmp_path / "run", timeout=60)

    verdicts = {result.probe: result.verdict for result in outcome.results}
    assert verdicts == {
        "cors": EXPOSED,
        "errors": EXPOSED,
        "secrets": EXPOSED,
        "database": EXPOSED,
    }
    assert outcome.summary[EXPOSED] == 4

    body = (tmp_path / "run" / "results.json").read_text(encoding="utf-8")
    assert "supersecretvalue123" not in body
    assert "[redacted]" in body
    assert tree_sha256(fixture) == before


def test_safe_fixture_reports_no_exposed(tmp_path):
    outcome = scan_local(
        str(FIXTURES / "safe-app"), out=tmp_path / "run", timeout=60
    )

    assert [result.verdict for result in outcome.results] == [NOT_REPRODUCED] * 4
    assert outcome.summary[EXPOSED] == 0


def test_declared_endpoint_without_auth_is_exposed(tmp_path):
    outcome = scan_local(
        str(FIXTURES / "vulnerable-app"),
        out=tmp_path / "run",
        timeout=60,
        endpoints=["/api/users"],
    )

    unauth = [result for result in outcome.results if result.probe == "unauth"]
    assert len(unauth) == 1
    assert unauth[0].verdict == EXPOSED
    headers = {name.lower() for name in unauth[0].request["headers"]}
    assert "authorization" not in headers
    assert "cookie" not in headers


def test_declared_endpoint_401_is_not_reproduced(tmp_path):
    outcome = scan_local(
        str(FIXTURES / "vulnerable-app"),
        out=tmp_path / "run",
        timeout=60,
        endpoints=["/api/private"],
    )

    unauth = [result for result in outcome.results if result.probe == "unauth"]
    assert [result.verdict for result in unauth] == [NOT_REPRODUCED]


def test_safe_declared_endpoint_is_not_reproduced(tmp_path):
    outcome = scan_local(
        str(FIXTURES / "safe-app"),
        out=tmp_path / "run",
        timeout=60,
        endpoints=["/api/users"],
    )

    unauth = [result for result in outcome.results if result.probe == "unauth"]
    assert [result.verdict for result in unauth] == [NOT_REPRODUCED]


def test_vulnerable_scan_writes_verifiable_bundles(tmp_path):
    outcome = scan_local(
        str(FIXTURES / "vulnerable-app"),
        out=tmp_path / "run",
        timeout=60,
        endpoints=["/api/users"],
    )

    exposed = [result for result in outcome.results if result.verdict == EXPOSED]
    assert len(exposed) == 5
    for result in exposed:
        assert result.proof is not None
        path = Path(result.proof)
        assert path.is_file()
        payload, fingerprint = verify_bundle(load_bundle(path))
        assert payload["finding"]["verdict"] == EXPOSED
        assert fingerprint.startswith("sha256:")


def test_safe_scan_writes_no_bundles(tmp_path):
    outcome = scan_local(
        str(FIXTURES / "safe-app"), out=tmp_path / "run", timeout=60
    )

    assert not any(result.verdict == EXPOSED for result in outcome.results)
    assert not (tmp_path / "run" / "proofs").exists()


def test_copied_bundle_verifies_without_the_run_dir(tmp_path):
    outcome = scan_local(
        str(FIXTURES / "vulnerable-app"), out=tmp_path / "run", timeout=60
    )
    exposed = next(
        result for result in outcome.results if result.verdict == EXPOSED
    )
    copied = tmp_path / "copied.json"
    shutil.copyfile(exposed.proof, str(copied))
    shutil.rmtree(tmp_path / "run")

    payload, fingerprint = verify_bundle(load_bundle(copied))

    assert payload["finding"]["probe"] == exposed.probe
    assert fingerprint.startswith("sha256:")


def test_sidecar_has_no_egress():
    docker = DockerRunner()
    network = "pry-net-egress-" + os.urandom(4).hex()
    sidecar = None
    docker.create_network(network)
    try:
        sidecar = docker.start_sidecar(
            network, "pry-egress-" + os.urandom(4).hex(), sidecar_script_path()
        )
        result = docker.exec(
            sidecar,
            [
                "python",
                "-c",
                "import urllib.request; "
                "urllib.request.urlopen('http://203.0.113.1/', timeout=3)",
            ],
            timeout=10,
        )
        assert result.returncode != 0
    finally:
        if sidecar is not None:
            docker.remove(sidecar)
        docker.remove_network(network)
