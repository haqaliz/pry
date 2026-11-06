"""Opt-in Docker integration tests (AT4/AT5/AT7/AT9).

Run with: PRY_DOCKER_TESTS=1 uv run pytest -q -m docker
These tests use local fixtures only; they never contact a third-party target.
"""

import os
from pathlib import Path

import pytest

from pry.intake.errors import BUILD_FAILED, IntakeError
from pry.intake.project import tree_sha256
from pry.intake.sandbox import intake

pytestmark = [
    pytest.mark.docker,
    pytest.mark.skipif(
        os.environ.get("PRY_DOCKER_TESTS") != "1",
        reason="set PRY_DOCKER_TESTS=1 to run Docker integration tests",
    ),
]

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"


def _run(name, out, timeout=60):
    return intake(str(FIXTURES / name), out=out, timeout=timeout)


def test_static_fixture_boots_and_cleans_up(tmp_path):
    fixture = FIXTURES / "static-site"
    before = tree_sha256(fixture)

    result = _run("static-site", tmp_path / "run", timeout=30)

    assert result.snapshot["result"]["status"] == "ready"
    assert result.snapshot["target"]["kind"] == "static"
    assert result.snapshot["sandbox"]["network"] == "none"
    assert tree_sha256(fixture) == before
    assert not result.workspace.exists()


def test_node_fixture_boots_and_cleans_up(tmp_path):
    result = _run("node-app", tmp_path / "run", timeout=60)

    assert result.snapshot["result"]["status"] == "ready"
    assert result.snapshot["target"]["kind"] == "node"
    assert result.snapshot["project"]["install"] == [
        "npm",
        "install",
        "--no-audit",
        "--no-fund",
    ]
    assert not result.workspace.exists()


def test_egress_is_blocked_in_the_run_phase(tmp_path):
    result = _run("egress-app", tmp_path / "run", timeout=60)

    log = (tmp_path / "run" / "run.log").read_text(encoding="utf-8")
    assert "EGRESS_FAILED" in log
    assert "EGRESS_OK" not in log
    assert result.snapshot["sandbox"]["network"] == "none"


def test_build_failure_writes_a_failure_snapshot(tmp_path):
    with pytest.raises(IntakeError) as exc:
        _run("broken-build", tmp_path / "run", timeout=60)

    assert exc.value.cause == BUILD_FAILED
    assert (tmp_path / "run" / "snapshot.json").is_file()
