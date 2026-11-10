"""Opt-in Docker integration for local findings reports (P6).

Run with: PRY_DOCKER_TESTS=1 uv run pytest -q -m docker
Local fixtures only; never a third-party target.
"""

import json
import os
from pathlib import Path

import pytest

from pry.probe.results import EXPOSED
from pry.probe.scan import scan_local
from pry.report import load_run, write_report

pytestmark = [
    pytest.mark.docker,
    pytest.mark.skipif(
        os.environ.get("PRY_DOCKER_TESTS") != "1",
        reason="set PRY_DOCKER_TESTS=1 to run Docker integration tests",
    ),
]

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"


@pytest.fixture(autouse=True)
def isolated_state(tmp_path, monkeypatch):
    monkeypatch.setenv("PRY_PROOF_KEY", str(tmp_path / "proof.key"))
    monkeypatch.setenv("PRY_CORPUS", str(tmp_path / "corpus.jsonl"))


def test_vulnerable_report_has_five_verified_findings(tmp_path):
    outcome = scan_local(
        str(FIXTURES / "vulnerable-app"),
        out=tmp_path / "run",
        timeout=60,
        endpoints=["/api/users"],
    )
    report_path = write_report(tmp_path / "run")

    report = load_run(tmp_path / "run")
    assert report.counts[EXPOSED] == 5
    assert all(
        finding.proof_status == "VALID"
        for finding in report.findings
        if finding.verdict == EXPOSED
    )

    text = report_path.read_text(encoding="utf-8")
    assert "Pry Findings Report" in text
    assert "What VALID means" in text
    assert "<script" not in text.lower()
    assert report_path.stat().st_mode & 0o777 == 0o600
    assert outcome.results_path.is_file()


def test_safe_report_has_no_exposed_findings(tmp_path):
    scan_local(
        str(FIXTURES / "safe-app"), out=tmp_path / "run", timeout=60
    )
    write_report(tmp_path / "run")

    report = load_run(tmp_path / "run")
    assert report.counts[EXPOSED] == 0


def test_tampered_proof_is_invalid_in_the_report(tmp_path):
    scan_local(
        str(FIXTURES / "vulnerable-app"), out=tmp_path / "run", timeout=60
    )
    report = load_run(tmp_path / "run")
    exposed = next(
        finding for finding in report.findings if finding.verdict == EXPOSED
    )
    proof_path = Path(exposed.proof)
    bundle = json.loads(proof_path.read_text(encoding="utf-8"))
    bundle["payload"]["finding"]["evidence"] = "tampered"
    proof_path.write_text(json.dumps(bundle), encoding="utf-8")

    tampered = load_run(tmp_path / "run")
    match = next(
        finding for finding in tampered.findings if finding.proof == exposed.proof
    )
    assert match.proof_status == "INVALID"
    assert match.fingerprint is None
