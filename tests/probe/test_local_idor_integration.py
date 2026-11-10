"""Opt-in Docker integration for configured local IDOR (AT1/AT5/AT8).

Run with: PRY_DOCKER_TESTS=1 uv run pytest -q -m docker
Local fixtures only; never a third-party target.
"""

import json
import os
from pathlib import Path

import pytest

from pry.probe.idor import load_idor_config
from pry.probe.results import EXPOSED
from pry.probe.scan import scan_local
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


def test_local_idor_is_reproduced_and_redacted(tmp_path):
    config_path = tmp_path / "idor.json"
    config_path.write_text(
        json.dumps(
            {
                "identity_a": {"headers": {"Cookie": "session=a"}},
                "identity_b": {"headers": {"Cookie": "session=b"}},
                "object_a": "/api/items/1",
                "object_b": "/api/items/2",
            }
        ),
        encoding="utf-8",
    )
    config_path.chmod(0o600)

    outcome = scan_local(
        str(FIXTURES / "vulnerable-app"),
        out=tmp_path / "run",
        timeout=60,
        idor_config=load_idor_config(config_path),
    )

    idor = next(result for result in outcome.results if result.probe == "idor")
    assert idor.verdict == EXPOSED
    assert idor.proof is not None
    assert idor.request["headers"].get("cookie") == "[redacted]"
    payload, fingerprint = verify_bundle(load_bundle(idor.proof))
    assert payload["finding"]["verdict"] == EXPOSED
    assert fingerprint.startswith("sha256:")

    write_report(tmp_path / "run")
    report = load_run(tmp_path / "run")
    assert report.counts[EXPOSED] >= 1
    report_text = (tmp_path / "run" / "report.html").read_text(encoding="utf-8")
    assert "idor" in report_text
    assert "session=a" not in report_text
    assert "session=b" not in report_text
    assert str(config_path) not in report_text

    for path in Path(tmp_path / "run").rglob("*"):
        if path.is_file():
            text = path.read_text(encoding="utf-8", errors="replace")
            assert "session=a" not in text
            assert "session=b" not in text
            assert str(config_path) not in text
