"""CLI intake tests (AT1/AT13)."""

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from pry.cli import main
from pry.intake.errors import BUILD_FAILED, IntakeError


def _result(tmp_path, kept=False):
    snapshot = {
        "sandbox_id": "pry-abc123",
        "target": {"path": "/tmp/repo", "kind": "node"},
        "project": {"image": "node:22-bookworm-slim"},
        "result": {"status": "ready"},
        "sandbox": {"container_id": "container123"},
    }
    return SimpleNamespace(
        snapshot_path=tmp_path / "snapshot.json",
        snapshot=snapshot,
        container_id="container123",
        workspace=tmp_path / "workspace",
        kept=kept,
    )


def test_intake_help_exits_zero():
    with pytest.raises(SystemExit) as exc:
        main(["intake", "--help"])
    assert exc.value.code == 0


def test_intake_missing_path_names_repo_not_found(capsys):
    assert main(["intake", "/does/not/exist"]) == 1
    assert "UNVERIFIED: REPO_NOT_FOUND" in capsys.readouterr().out


def test_intake_success_prints_summary(monkeypatch, capsys, tmp_path):
    monkeypatch.setattr("pry.cli.intake", lambda *a, **k: _result(tmp_path))

    assert main(["intake", "."]) == 0
    out = capsys.readouterr().out
    assert "Sandbox ready: pry-abc123" in out
    assert "Snapshot: %s" % (tmp_path / "snapshot.json") in out
    assert "Image: node:22-bookworm-slim" in out
    assert "Container: container123" in out
    assert "Clean up with" not in out


def test_intake_json_includes_snapshot_and_path(monkeypatch, capsys, tmp_path):
    monkeypatch.setattr("pry.cli.intake", lambda *a, **k: _result(tmp_path))

    assert main(["intake", ".", "--json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["sandbox_id"] == "pry-abc123"
    assert data["snapshot_path"] == str(tmp_path / "snapshot.json")


def test_intake_keep_prints_cleanup(monkeypatch, capsys, tmp_path):
    monkeypatch.setattr("pry.cli.intake", lambda *a, **k: _result(tmp_path, kept=True))

    assert main(["intake", ".", "--keep"]) == 0
    out = capsys.readouterr().out
    assert "Container: container123 (kept)" in out
    assert "docker rm -f container123" in out
    assert "rm -rf %s" % (tmp_path / "workspace") in out


def test_intake_failure_names_the_cause(monkeypatch, capsys):
    def fail(*args, **kwargs):
        raise IntakeError(BUILD_FAILED, "npm ERR!")

    monkeypatch.setattr("pry.cli.intake", fail)

    assert main(["intake", "."]) == 1
    out = capsys.readouterr().out
    assert "UNVERIFIED: BUILD_FAILED" in out
    assert "npm ERR!" in out


def test_intake_failure_json(monkeypatch, capsys):
    def fail(*args, **kwargs):
        raise IntakeError(BUILD_FAILED, "npm ERR!")

    monkeypatch.setattr("pry.cli.intake", fail)

    assert main(["intake", ".", "--json"]) == 1
    data = json.loads(capsys.readouterr().out)
    assert data == {
        "status": "failed",
        "cause": BUILD_FAILED,
        "message": "npm ERR!",
    }


def test_intake_rejects_non_integer_port():
    with pytest.raises(SystemExit) as exc:
        main(["intake", ".", "--port", "abc"])
    assert exc.value.code == 2
