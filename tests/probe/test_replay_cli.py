"""CLI live proof replay tests (AT1-AT4, AT8)."""

import json
from pathlib import Path

import pytest

from pry.cli import main
from pry.own.target import normalize_target
from pry.own.tokens import TokenSigner
from pry.probe import replay
from pry.proof import build_bundle, write_bundle

TARGET_URL = "https://app.example.com"
TARGET = {
    "sandbox_id": "live-0123456789ab",
    "path": TARGET_URL,
    "kind": "live",
    "url": TARGET_URL,
    "ownership_proof": "dns_txt",
    "git_commit": None,
    "git_dirty": None,
    "tree_sha256": None,
    "image": None,
    "image_digest": None,
    "port": None,
}
FINDING = {
    "probe": "cors",
    "verdict": "EXPOSED",
    "cause": None,
    "evidence": "CORS reflects the origin with credentials",
    "request": {
        "method": "GET",
        "url": TARGET_URL + "/",
        "headers": {"origin": "https://pry.invalid", "user-agent": "pry/0.1"},
    },
    "response": {"status": 200, "headers": {}, "body": "ok"},
}


@pytest.fixture(autouse=True)
def isolated_keys(tmp_path, monkeypatch):
    monkeypatch.setenv("PRY_KEY_FILE", str(tmp_path / "ownership.key"))
    monkeypatch.setenv("PRY_PROOF_KEY", str(tmp_path / "proof.key"))


def _token(target=TARGET_URL):
    return TokenSigner().issue(normalize_target(target), "dns_txt")


def _bundle_file(tmp_path):
    bundle = build_bundle(dict(TARGET), dict(FINDING))
    path = write_bundle(tmp_path / "run", bundle)
    return path


def _result(status=replay.MATCH):
    if status == replay.UNVERIFIED:
        return {
            "status": replay.UNVERIFIED,
            "probe": "cors",
            "target": TARGET_URL,
            "recorded_status": 200,
            "cause": "TARGET_UNREACHABLE",
            "message": "replay failed: connection refused",
        }
    return {
        "status": status,
        "probe": "cors",
        "target": TARGET_URL,
        "recorded_status": 200,
        "replay_status": 200 if status == replay.MATCH else 403,
        "body_bytes": 2,
        "message": "status match only" if status == replay.MATCH else "differs",
    }


@pytest.fixture
def fake_replay(monkeypatch):
    calls = []

    def fake(payload, token):
        calls.append((payload, token))
        return _result()

    monkeypatch.setattr("pry.cli.replay_bundle", fake)
    return calls


def test_replay_match_exits_zero_and_prints_the_status(
    tmp_path, fake_replay, capsys
):
    path = _bundle_file(tmp_path)

    code = main(["replay", str(path), "--token", _token()])

    assert code == 0
    out = capsys.readouterr().out
    assert "MATCH" in out
    assert "200" in out
    assert "status match only" in out
    assert len(fake_replay) == 1


def test_replay_mismatch_exits_one(tmp_path, fake_replay, capsys):
    path = _bundle_file(tmp_path)

    import pry.cli as cli

    cli.replay_bundle = lambda payload, token: _result(replay.MISMATCH)

    assert main(["replay", str(path), "--token", _token()]) == 1
    out = capsys.readouterr().out
    assert "MISMATCH" in out
    assert "403" in out


def test_replay_unverified_exits_two(tmp_path, fake_replay, capsys):
    path = _bundle_file(tmp_path)
    import pry.cli as cli

    cli.replay_bundle = lambda payload, token: _result(replay.UNVERIFIED)

    assert main(["replay", str(path), "--token", _token()]) == 2
    out = capsys.readouterr().out
    assert "UNVERIFIED" in out
    assert "TARGET_UNREACHABLE" in out


def test_replay_json_includes_the_statuses(tmp_path, fake_replay, capsys):
    path = _bundle_file(tmp_path)

    code = main(["replay", str(path), "--token", _token(), "--json"])

    assert code == 0
    data = json.loads(capsys.readouterr().out)
    assert data["status"] == replay.MATCH
    assert data["recorded_status"] == 200
    assert data["replay_status"] == 200


def test_an_invalid_bundle_exits_two_before_replay(
    tmp_path, fake_replay, capsys
):
    path = tmp_path / "bundle.json"
    path.write_text("not a bundle", encoding="utf-8")

    assert main(["replay", str(path), "--token", _token()]) == 2
    assert fake_replay == []
    assert "UNVERIFIED" in capsys.readouterr().out


def test_a_missing_token_exits_two_before_replay(
    tmp_path, fake_replay, capsys
):
    path = _bundle_file(tmp_path)

    assert main(["replay", str(path)]) == 2
    assert fake_replay == []
    assert "TOKEN_MALFORMED" in capsys.readouterr().out


def test_the_fingerprint_pin_is_enforced(tmp_path, fake_replay, capsys):
    path = _bundle_file(tmp_path)

    code = main(
        [
            "replay",
            str(path),
            "--token",
            _token(),
            "--fingerprint",
            "sha256:" + "0" * 64,
        ]
    )

    assert code == 2
    assert fake_replay == []
    assert "PROOF_FINGERPRINT_MISMATCH" in capsys.readouterr().out
