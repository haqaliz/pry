"""Deterministic run directories, pinned snapshots, and capped logs."""

import json
import os
import secrets
from datetime import datetime, timezone
from pathlib import Path

from pry.intake.errors import SNAPSHOT_FAILED, IntakeError

LOG_LIMIT = 1024 * 1024


def snapshot_id() -> str:
    return "pry-" + secrets.token_hex(6)


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def new_run_dir(out=None, home=None) -> Path:
    if out is None:
        base = Path(home) if home is not None else Path.home()
        path = base / ".pry" / "runs" / snapshot_id()
    else:
        path = Path(out)
    try:
        path.mkdir(parents=True, exist_ok=True)
        os.chmod(str(path), 0o700)
    except OSError as exc:
        raise IntakeError(
            SNAPSHOT_FAILED, "cannot create run directory %s: %s" % (path, exc)
        ) from exc
    return path


def write_snapshot(run_dir: Path, snapshot: dict) -> Path:
    run_dir = Path(run_dir)
    target = run_dir / "snapshot.json"
    temp = run_dir / "snapshot.json.tmp"
    try:
        payload = json.dumps(snapshot, sort_keys=True, indent=2) + "\n"
        temp.write_text(payload, encoding="utf-8")
        os.chmod(str(temp), 0o600)
        os.replace(str(temp), str(target))
    except (OSError, TypeError, ValueError) as exc:
        try:
            temp.unlink()
        except OSError:
            pass
        raise IntakeError(
            SNAPSHOT_FAILED, "cannot write snapshot: %s" % exc
        ) from exc
    return target


def write_log(run_dir: Path, name: str, data: bytes) -> Path:
    path = Path(run_dir) / name
    if len(data) > LOG_LIMIT:
        marker = b"\n[truncated at %d bytes]\n" % LOG_LIMIT
        data = data[: LOG_LIMIT - len(marker)] + marker
    try:
        path.write_bytes(data)
        os.chmod(str(path), 0o600)
    except OSError as exc:
        raise IntakeError(
            SNAPSHOT_FAILED, "cannot write log %s: %s" % (name, exc)
        ) from exc
    return path
