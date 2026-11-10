"""Opt-in Docker integration for local Level 2 write confirmation (AT1/AT9).

Run with: PRY_DOCKER_TESTS=1 uv run pytest -q -m docker
Local fixtures only; the write runs against the disposable sandbox copy.
"""

import json
import os
import tempfile
from pathlib import Path

import pytest

from pry.probe.results import EXPOSED, NOT_REPRODUCED
from pry.probe.scan import scan_local
from pry.probe.write import load_write_config
from pry.proof import load_bundle, verify_bundle
from pry.report import load_run, write_report

pytestmark = [
    pytest.mark.docker,
    pytest.mark.skipif(
        os.environ.get("PRY_DOCKER_TESTS") != "1",
        reason="set PRY_DOCKER_TESTS=1 to run Docker integration tests",
    ),
]

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"
WRITE_CONFIG = {
    "method": "POST",
    "endpoint": "/api/write",
    "body": '{"name":"{{marker}}"}',
    "verify_endpoint": "/api/write",
    "verify_contains": "{{marker}}",
}


@pytest.fixture(autouse=True)
def isolated_state(tmp_path, monkeypatch):
    monkeypatch.setenv("PRY_PROOF_KEY", str(tmp_path / "proof.key"))
    monkeypatch.setenv("PRY_CORPUS", str(tmp_path / "corpus.jsonl"))


def _config(tmp_path):
    path = tmp_path / "write.json"
    path.write_text(json.dumps(WRITE_CONFIG), encoding="utf-8")
    path.chmod(0o600)
    return path


def _leftover_write_configs():
    return set(Path(tempfile.gettempdir()).glob("pry-write-*"))


def test_a_declared_write_is_reproduced_and_read_back(tmp_path):
    before = _leftover_write_configs()
    config_path = _config(tmp_path)

    outcome = scan_local(
        str(FIXTURES / "vulnerable-app"),
        out=tmp_path / "run",
        timeout=60,
        write_config=load_write_config(config_path),
    )

    write = next(result for result in outcome.results if result.probe == "write")
    assert write.verdict == EXPOSED
    assert write.proof is not None
    assert write.response["status"] == 201
    verification = write.response["verification"]
    assert verification["request"]["method"] == "GET"
    assert verification["response"]["status"] == 200
    assert "pry-" in verification["response"]["body"]
    assert str(config_path) not in json.dumps(write.response)

    payload, fingerprint = verify_bundle(load_bundle(write.proof))
    assert payload["finding"]["verdict"] == EXPOSED
    assert payload["finding"]["probe"] == "write"
    assert payload["finding"]["response"]["verification"]["response"]["status"] == 200
    assert fingerprint.startswith("sha256:")

    write_report(tmp_path / "run")
    report = load_run(tmp_path / "run")
    assert report.counts[EXPOSED] >= 1
    report_text = (tmp_path / "run" / "report.html").read_text(encoding="utf-8")
    assert "write" in report_text
    assert "201" in report_text
    assert str(config_path) not in report_text

    for path in Path(tmp_path / "run").rglob("*"):
        if path.is_file():
            text = path.read_text(encoding="utf-8", errors="replace")
            assert str(config_path) not in text
    assert _leftover_write_configs() == before


def test_a_rejected_write_is_not_reproduced(tmp_path):
    config_path = _config(tmp_path)

    outcome = scan_local(
        str(FIXTURES / "safe-app"),
        out=tmp_path / "run",
        timeout=60,
        write_config=load_write_config(config_path),
    )

    write = next(result for result in outcome.results if result.probe == "write")
    assert write.verdict == NOT_REPRODUCED
    assert write.proof is None
    assert write.response["status"] == 401
    assert "verification" not in write.response
