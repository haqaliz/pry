"""CLI intake skeleton tests (AT1)."""

from pathlib import Path
from types import SimpleNamespace

import pytest

from pry.cli import main


def test_intake_help_exits_zero():
    with pytest.raises(SystemExit) as exc:
        main(["intake", "--help"])
    assert exc.value.code == 0


def test_intake_missing_path_names_repo_not_found(capsys):
    assert main(["intake", "/does/not/exist"]) == 1
    out = capsys.readouterr().out
    assert "UNVERIFIED: REPO_NOT_FOUND" in out


def test_intake_success_prints_snapshot_path(monkeypatch, capsys):
    snapshot = Path("/tmp/pry-run/snapshot.json")
    monkeypatch.setattr(
        "pry.cli.intake",
        lambda *args, **kwargs: SimpleNamespace(snapshot_path=snapshot),
    )

    assert main(["intake", "."]) == 0
    assert str(snapshot) in capsys.readouterr().out
