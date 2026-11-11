"""CLI provider database check tests (AT1-AT8).

The probe's fetch is scripted; nothing here opens a socket.
"""

import json
import os
from pathlib import Path

import pytest

import pry.probe.database_rules as database_rules
from pry.cli import main
from pry.probe.database_rules import (
    DATABASE_MARKER_CONFIRMATION_REQUIRED,
    DATABASE_MARKER_MISMATCH,
)
from pry.probe.results import EXPOSED, NOT_REPRODUCED
from pry.probe.sidecar import Response
from pry.proof import load_bundle, verify_bundle

FIREBASE_URL = "https://demo.firebaseio.com"
SUPABASE_URL = "https://project.supabase.co"
MARKER = "pry-test-marker-abc123"
ANON_KEY = "anon-key-1234567890"
MARKER_PATH = "/pry_ownership.json"
FIREBASE_DATA_PATH = "/users.json"
SUPABASE_MARKER_PATH = "/rest/v1/pry_ownership?select=marker"
SUPABASE_DATA_PATH = "/rest/v1/users?select=*"


@pytest.fixture(autouse=True)
def isolated_keys(tmp_path, monkeypatch):
    monkeypatch.setenv("PRY_PROOF_KEY", str(tmp_path / "proof.key"))


def _firebase_payload(**overrides):
    data = {
        "provider": "firebase-rtdb",
        "url": FIREBASE_URL,
        "marker_path": MARKER_PATH,
        "marker": MARKER,
        "read_path": FIREBASE_DATA_PATH,
    }
    data.update(overrides)
    return data


def _supabase_payload(**overrides):
    data = {
        "provider": "supabase",
        "url": SUPABASE_URL,
        "marker_path": SUPABASE_MARKER_PATH,
        "marker": MARKER,
        "read_path": SUPABASE_DATA_PATH,
        "anon_key": ANON_KEY,
    }
    data.update(overrides)
    return data


def _write_config(tmp_path, data, mode=0o600):
    path = tmp_path / "db.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    os.chmod(str(path), mode)
    return path


def _response(url, body="", status=200):
    return Response(
        status, {"Content-Type": "application/json"}, body, url
    )


class FakeFetch:
    """Records each request and returns scripted responses."""

    def __init__(self, *responses):
        self.responses = list(responses)
        self.calls = []

    def __call__(self, method, url, headers):
        self.calls.append((method, url, dict(headers)))
        return self.responses.pop(0)


@pytest.fixture
def install_fetch(monkeypatch):
    def install(*responses):
        fetch = FakeFetch(*responses)
        monkeypatch.setattr(database_rules, "urllib_fetch", fetch)
        return fetch

    return install


def _database_argv(config_path, out, *extra):
    return [
        "database",
        "--config",
        str(config_path),
        "--confirm-marker",
        "--out",
        str(out),
    ] + list(extra)


def test_the_marker_confirmation_is_required(tmp_path, capsys):
    config_path = _write_config(tmp_path, _firebase_payload())
    run_dir = tmp_path / "run"

    assert (
        main(
            [
                "database",
                "--config",
                str(config_path),
                "--out",
                str(run_dir),
            ]
        )
        == 2
    )

    out = capsys.readouterr().out
    assert "UNVERIFIED" in out
    assert DATABASE_MARKER_CONFIRMATION_REQUIRED in out
    assert "control attestation" in out
    assert "DNS-grade" in out
    assert not run_dir.exists()


def test_an_invalid_config_exits_two_before_any_run_dir(
    tmp_path, capsys
):
    config_path = _write_config(
        tmp_path, _firebase_payload(), mode=0o644
    )
    run_dir = tmp_path / "run"

    assert main(_database_argv(config_path, run_dir)) == 2

    out = capsys.readouterr().out
    assert "DATABASE_CONFIG_INVALID" in out
    assert str(config_path) not in out
    assert not run_dir.exists()


def test_an_exposed_result_is_signed_and_reported_in_json(
    tmp_path, capsys, install_fetch
):
    config_path = _write_config(tmp_path, _supabase_payload())
    fetch = install_fetch(
        _response(
            SUPABASE_URL + SUPABASE_MARKER_PATH,
            json.dumps([{"marker": MARKER}]),
        ),
        _response(SUPABASE_URL + SUPABASE_DATA_PATH, '[{"id":1}]'),
    )
    run_dir = tmp_path / "run"

    assert (
        main(_database_argv(config_path, run_dir, "--json")) == 1
    )

    raw = capsys.readouterr().out
    data = json.loads(raw)
    assert set(data) == {
        "results",
        "summary",
        "results_path",
        "proof",
    }
    assert data["summary"][EXPOSED] == 1
    assert data["results"][0]["probe"] == "database_rules"
    assert data["results"][0]["verdict"] == EXPOSED
    assert data["results_path"] == str(run_dir / "results.json")

    payload, fingerprint = verify_bundle(load_bundle(data["proof"]))
    assert payload["finding"]["verdict"] == EXPOSED
    assert payload["finding"]["probe"] == "database_rules"
    assert payload["finding"]["response"]["ownership"]["request"]["url"] == (
        SUPABASE_URL + SUPABASE_MARKER_PATH
    )
    assert fingerprint.startswith("sha256:")

    snapshot = json.loads(
        (run_dir / "snapshot.json").read_text(encoding="utf-8")
    )
    assert snapshot["target"]["kind"] == "database"
    assert snapshot["target"]["url"] == SUPABASE_URL
    assert snapshot["target"]["ownership_proof"] == "database_marker"
    assert snapshot["sandbox"]["network"] == "live"
    assert snapshot["sandbox"]["internal_url"] == SUPABASE_URL

    assert fetch.calls[0][1] == SUPABASE_URL + SUPABASE_MARKER_PATH
    assert fetch.calls[1][1] == SUPABASE_URL + SUPABASE_DATA_PATH

    texts = [
        raw,
        (run_dir / "results.json").read_text(encoding="utf-8"),
        (run_dir / "snapshot.json").read_text(encoding="utf-8"),
        Path(data["proof"]).read_text(encoding="utf-8"),
        (tmp_path / "corpus.jsonl").read_text(encoding="utf-8"),
    ]
    for text in texts:
        assert ANON_KEY not in text
        assert str(config_path) not in text


def test_a_not_reproduced_result_exits_zero_without_a_proof(
    tmp_path, capsys, install_fetch
):
    config_path = _write_config(tmp_path, _firebase_payload())
    install_fetch(
        _response(FIREBASE_URL + MARKER_PATH, json.dumps(MARKER)),
        _response(FIREBASE_URL + FIREBASE_DATA_PATH, "", status=404),
    )
    run_dir = tmp_path / "run"

    assert (
        main(_database_argv(config_path, run_dir, "--json")) == 0
    )

    data = json.loads(capsys.readouterr().out)
    assert set(data) == {"results", "summary", "results_path"}
    assert data["summary"][NOT_REPRODUCED] == 1
    assert (run_dir / "results.json").is_file()


def test_plain_output_prints_the_result_and_results_path(
    tmp_path, capsys, install_fetch
):
    config_path = _write_config(tmp_path, _firebase_payload())
    install_fetch(
        _response(FIREBASE_URL + MARKER_PATH, json.dumps(MARKER)),
        _response(FIREBASE_URL + FIREBASE_DATA_PATH, "{}"),
    )
    run_dir = tmp_path / "run"

    assert main(_database_argv(config_path, run_dir)) == 0

    out = capsys.readouterr().out
    assert "database_rules: NOT_REPRODUCED:" in out
    assert "Results: %s" % (run_dir / "results.json") in out
    assert "Proof:" not in out


def test_a_marker_mismatch_exits_two_without_results(
    tmp_path, capsys, install_fetch
):
    config_path = _write_config(tmp_path, _firebase_payload())
    install_fetch(
        _response(FIREBASE_URL + MARKER_PATH, '"another-marker-value"')
    )
    run_dir = tmp_path / "run"

    assert main(_database_argv(config_path, run_dir)) == 2

    out = capsys.readouterr().out
    assert DATABASE_MARKER_MISMATCH in out
    assert "configured marker not found" in out
    assert not run_dir.exists()
    assert not (run_dir / "results.json").exists()
