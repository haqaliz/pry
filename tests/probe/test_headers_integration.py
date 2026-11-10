"""Opt-in Docker integration for header observations (AT7).

Run with: PRY_DOCKER_TESTS=1 uv run pytest -q -m docker
Local fixtures only; never a third-party target.
"""

import os
from pathlib import Path

import pytest

from pry.probe.headers import OBSERVED
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


def test_vulnerable_fixture_reports_missing_headers(tmp_path):
    outcome = scan_local(
        str(FIXTURES / "vulnerable-app"),
        out=tmp_path / "run",
        timeout=60,
        headers=True,
    )

    observation = next(
        entry for entry in outcome.observations if entry["probe"] == "headers"
    )
    assert observation["status"] == OBSERVED
    assert "content-security-policy" in observation["missing"]
    assert "proof" not in observation
    assert "verdict" not in observation

    write_report(tmp_path / "run")
    report = load_run(tmp_path / "run")
    assert report.observations[0]["probe"] == "headers"
    text = (tmp_path / "run" / "report.html").read_text(encoding="utf-8")
    assert "Missing:" in text
    assert "content-security-policy" in text
    assert "not a verdict" in text
    assert "<script" not in text.lower()


def test_safe_fixture_reports_present_headers(tmp_path):
    outcome = scan_local(
        str(FIXTURES / "safe-app"),
        out=tmp_path / "run",
        timeout=60,
        headers=True,
    )

    observation = next(
        entry for entry in outcome.observations if entry["probe"] == "headers"
    )
    assert observation["status"] == OBSERVED
    assert observation["missing"] == []
    assert "content-security-policy" in observation["present"]
