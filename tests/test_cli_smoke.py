"""Packaging smoke test: the pry package and entry point must exist."""

import pytest

from pry.cli import main


def test_help_exits_zero():
    with pytest.raises(SystemExit) as exc:
        main(["--help"])
    assert exc.value.code == 0


def test_no_command_returns_one():
    assert main([]) == 1
