"""Local repository intake for Pry."""

from pathlib import Path

from pry.intake.errors import REPO_NOT_FOUND, SANDBOX_ERROR, IntakeError


def intake(path, *, out=None, keep=False, port=None, timeout=None, docker=None):
    """Boot a local repository in a sandbox (orchestration lands in a later phase)."""
    if not Path(path).is_dir():
        raise IntakeError(REPO_NOT_FOUND, "not a directory: %s" % path)
    raise IntakeError(SANDBOX_ERROR, "not implemented")


__all__ = ["IntakeError", "intake"]
