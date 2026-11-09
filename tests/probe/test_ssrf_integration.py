"""Opt-in Docker integration for local SSRF Level 1 (AT1/AT2).

Run with: PRY_DOCKER_TESTS=1 uv run pytest -q -m docker
Local fixtures only; never a third-party target.
"""

import os
from pathlib import Path
from urllib.parse import unquote

import pytest

from pry.probe.results import EXPOSED, NOT_REPRODUCED
from pry.probe.scan import scan_local
from pry.probe.ssrf import SsrfConfig
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


@pytest.fixture(autouse=True)
def isolated_state(tmp_path, monkeypatch):
    monkeypatch.setenv("PRY_PROOF_KEY", str(tmp_path / "proof.key"))
    monkeypatch.setenv("PRY_CORPUS", str(tmp_path / "corpus.jsonl"))


def test_local_ssrf_callback_hit_is_exposed(tmp_path):
    outcome = scan_local(
        str(FIXTURES / "vulnerable-app"),
        out=tmp_path / "run",
        timeout=60,
        ssrf_config=SsrfConfig("/api/fetch", "url"),
    )

    ssrf = next(result for result in outcome.results if result.probe == "ssrf")
    assert ssrf.verdict == EXPOSED
    assert ssrf.proof is not None
    assert "pry-callback:9000" in unquote(ssrf.request["url"])
    assert "callback recorded" in ssrf.evidence
    payload, fingerprint = verify_bundle(load_bundle(ssrf.proof))
    assert payload["finding"]["verdict"] == EXPOSED
    assert fingerprint.startswith("sha256:")

    report_path = write_report(tmp_path / "run")
    report = load_run(tmp_path / "run")
    assert report.counts[EXPOSED] >= 1
    text = report_path.read_text(encoding="utf-8")
    assert "ssrf" in text
    assert "callback recorded" in text


def test_safe_fixture_does_not_fetch_the_callback(tmp_path):
    outcome = scan_local(
        str(FIXTURES / "safe-app"),
        out=tmp_path / "run",
        timeout=60,
        ssrf_config=SsrfConfig("/api/fetch", "url"),
    )

    ssrf = next(result for result in outcome.results if result.probe == "ssrf")
    assert ssrf.verdict == NOT_REPRODUCED
    assert ssrf.proof is None
