"""Opt-in Docker integration for the local rate-limit observation (AT8).

Run with: PRY_DOCKER_TESTS=1 uv run pytest -q -m docker
Local fixtures only; never a third-party target.
"""

import os
from pathlib import Path

import pytest

from pry.probe.rate_limit import OBSERVED, THROTTLED, RateLimitConfig
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


def test_throttled_endpoint_is_observed(tmp_path):
    outcome = scan_local(
        str(FIXTURES / "vulnerable-app"),
        out=tmp_path / "run",
        timeout=60,
        rate_limit_config=RateLimitConfig("/api/rate-limit", 10),
    )

    assert len(outcome.observations) == 1
    observation = outcome.observations[0]
    assert observation["status"] == THROTTLED
    assert "request 4/10" in observation["evidence"]
    assert "proof" not in observation
    assert "verdict" not in observation

    write_report(tmp_path / "run")
    report = load_run(tmp_path / "run")
    assert report.observations[0]["status"] == THROTTLED
    text = (tmp_path / "run" / "report.html").read_text(encoding="utf-8")
    assert "Observations" in text
    assert "THROTTLED" in text
    assert "not a verdict" in text


def test_unthrottled_endpoint_is_observed(tmp_path):
    outcome = scan_local(
        str(FIXTURES / "vulnerable-app"),
        out=tmp_path / "run",
        timeout=60,
        rate_limit_config=RateLimitConfig("/api/no-limit", 10),
    )

    assert len(outcome.observations) == 1
    observation = outcome.observations[0]
    assert observation["status"] == OBSERVED
    assert "10 requests accepted without throttling" in observation["evidence"]
    assert "proof" not in observation
    assert "verdict" not in observation
