"""Opt-in Docker integration for served database files (AT7).

Run with: PRY_DOCKER_TESTS=1 uv run pytest -q -m docker
Local fixtures only; never a third-party target.
"""

import os
from pathlib import Path

import pytest

from pry.probe.results import EXPOSED, NOT_REPRODUCED
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
FAKE_ROW = "fixture-row@example.invalid"


@pytest.fixture(autouse=True)
def isolated_state(tmp_path, monkeypatch):
    monkeypatch.setenv("PRY_PROOF_KEY", str(tmp_path / "proof.key"))
    monkeypatch.setenv("PRY_CORPUS", str(tmp_path / "corpus.jsonl"))


def test_served_sql_dump_is_exposed_and_rows_are_not_stored(tmp_path):
    outcome = scan_local(
        str(FIXTURES / "vulnerable-app"), out=tmp_path / "run", timeout=60
    )

    database = next(
        result for result in outcome.results if result.probe == "database"
    )
    assert database.verdict == EXPOSED
    assert database.proof is not None
    assert "SQL dump content withheld" in database.response["body"]
    assert FAKE_ROW not in str(outcome.results)

    payload, fingerprint = verify_bundle(load_bundle(database.proof))
    assert payload["finding"]["verdict"] == EXPOSED
    assert payload["finding"]["probe"] == "database"
    assert fingerprint.startswith("sha256:")

    write_report(tmp_path / "run")
    report = load_run(tmp_path / "run")
    assert report.counts[EXPOSED] >= 1
    report_text = (tmp_path / "run" / "report.html").read_text(encoding="utf-8")
    assert "database" in report_text
    assert FAKE_ROW not in report_text

    for path in Path(tmp_path / "run").rglob("*"):
        if path.is_file():
            text = path.read_text(encoding="utf-8", errors="replace")
            assert FAKE_ROW not in text


def test_safe_fixture_has_no_database_exposure(tmp_path):
    outcome = scan_local(
        str(FIXTURES / "safe-app"), out=tmp_path / "run", timeout=60
    )

    database = next(
        result for result in outcome.results if result.probe == "database"
    )
    assert database.verdict == NOT_REPRODUCED
    assert database.proof is None
