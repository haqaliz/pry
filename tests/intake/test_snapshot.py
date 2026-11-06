"""Run directory, pinned snapshot, and capped log tests (AT11/AT12)."""

import json
import stat
from datetime import datetime

import pytest

from pry.intake.errors import SANDBOX_ERROR, SNAPSHOT_FAILED, IntakeError
from pry.intake.snapshot import (
    LOG_LIMIT,
    new_run_dir,
    snapshot_id,
    utc_now,
    write_log,
    write_snapshot,
)

SNAPSHOT = {
    "version": 1,
    "sandbox_id": "pry-0123456789ab",
    "created_at": "2026-11-07T00:00:00Z",
    "target": {
        "path": "/tmp/app",
        "resolved_path": "/tmp/app",
        "is_git": False,
        "git_commit": None,
        "git_dirty": None,
        "tree_sha256": "a" * 64,
    },
    "project": {
        "kind": "static",
        "package_manager": None,
        "lockfile_sha256": None,
        "image": "python:3.9-slim",
        "image_digest": "sha256:" + "b" * 64,
        "install": None,
        "build": None,
        "start": ["python", "-m", "http.server"],
        "port": 8000,
    },
    "sandbox": {
        "container_id": "c" * 64,
        "network": "none",
        "memory": "2g",
        "cpus": "2",
        "pids": 512,
    },
    "result": {"status": "ready"},
}


def _mode(path):
    return stat.S_IMODE(path.stat().st_mode)


def test_new_run_dir_uses_home_and_creates_0700(tmp_path):
    run_dir = new_run_dir(home=tmp_path)

    assert run_dir.parent == tmp_path / ".pry" / "runs"
    assert run_dir.name.startswith("pry-")
    assert len(run_dir.name) == len("pry-") + 12
    assert _mode(run_dir) == 0o700


def test_new_run_dir_out_is_the_exact_run_dir(tmp_path):
    out = tmp_path / "custom-run"

    assert new_run_dir(out=out, home=tmp_path / "ignored") == out
    assert _mode(out) == 0o700


def test_snapshot_id_is_prefixed_hex_and_unique():
    first = snapshot_id()
    second = snapshot_id()

    assert first.startswith("pry-")
    assert len(first) == len("pry-") + 12
    assert all(char in "0123456789abcdef" for char in first[4:])
    assert first != second


def test_utc_now_is_iso_8601_z():
    value = utc_now()

    assert value.endswith("Z")
    datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")


def test_write_snapshot_is_atomic_sorted_and_0600(tmp_path):
    run_dir = new_run_dir(out=tmp_path / "run")

    path = write_snapshot(run_dir, SNAPSHOT)

    assert path == run_dir / "snapshot.json"
    assert _mode(path) == 0o600
    assert not (run_dir / "snapshot.json.tmp").exists()
    assert path.read_text() == json.dumps(SNAPSHOT, sort_keys=True, indent=2) + "\n"
    data = json.loads(path.read_text())
    assert set(data) >= {
        "version",
        "sandbox_id",
        "created_at",
        "target",
        "project",
        "sandbox",
        "result",
    }


def test_write_snapshot_is_byte_identical_for_same_data(tmp_path):
    run_dir = new_run_dir(out=tmp_path / "run")

    first = write_snapshot(run_dir, SNAPSHOT).read_bytes()
    second = write_snapshot(run_dir, SNAPSHOT).read_bytes()

    assert first == second


def test_failure_snapshot_records_status_and_cause(tmp_path):
    run_dir = new_run_dir(out=tmp_path / "run")
    failed = dict(SNAPSHOT)
    failed["result"] = {
        "status": "failed",
        "cause": SANDBOX_ERROR,
        "message": "boom",
    }

    data = json.loads(write_snapshot(run_dir, failed).read_text())

    assert data["result"]["status"] == "failed"
    assert data["result"]["cause"] == SANDBOX_ERROR


def test_write_snapshot_maps_oserror_to_snapshot_failed(tmp_path):
    with pytest.raises(IntakeError) as exc:
        write_snapshot(tmp_path / "missing", SNAPSHOT)

    assert exc.value.cause == SNAPSHOT_FAILED


def test_write_log_keeps_small_data_exact_and_0600(tmp_path):
    run_dir = new_run_dir(out=tmp_path / "run")

    path = write_log(run_dir, "build.log", b"hello\n")

    assert path == run_dir / "build.log"
    assert path.read_bytes() == b"hello\n"
    assert _mode(path) == 0o600


def test_write_log_caps_at_one_mib_with_marker(tmp_path):
    run_dir = new_run_dir(out=tmp_path / "run")

    path = write_log(run_dir, "build.log", b"x" * (2 * LOG_LIMIT))

    body = path.read_bytes()
    assert path.stat().st_size <= LOG_LIMIT
    assert body.startswith(b"x" * 1024)
    assert b"truncated" in body
    assert _mode(path) == 0o600
