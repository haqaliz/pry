"""CLI verify-proof tests (AT11).

The bundle is built locally under tmp_path; no run directory is needed.
"""

import base64
import copy
import json

import pytest

from pry.cli import main
from pry.proof import build_bundle

TARGET = {
    "sandbox_id": "pry-0123456789ab",
    "path": "/repo",
    "kind": "static",
    "git_commit": "a" * 40,
    "git_dirty": False,
    "tree_sha256": "b" * 64,
    "image": "python:3.9-slim",
    "image_digest": "sha256:" + "c" * 64,
    "port": 8000,
}

FINDING = {
    "probe": "cors",
    "verdict": "EXPOSED",
    "cause": None,
    "evidence": "Access-Control-Allow-Origin reflects https://pry.invalid",
    "request": {
        "method": "GET",
        "url": "http://app:8000/",
        "headers": {"origin": "https://pry.invalid"},
    },
    "response": {
        "status": 200,
        "headers": {"access-control-allow-origin": "https://pry.invalid"},
        "body": "ok",
    },
}


@pytest.fixture(autouse=True)
def proof_key(tmp_path, monkeypatch):
    path = tmp_path / "proof.key"
    monkeypatch.setenv("PRY_PROOF_KEY", str(path))
    return path


def _bundle():
    return build_bundle(
        copy.deepcopy(TARGET),
        copy.deepcopy(FINDING),
        created_at="2026-11-08T00:00:00Z",
    )


def _write(tmp_path, bundle, name="bundle.json"):
    path = tmp_path / name
    path.write_text(json.dumps(bundle), encoding="utf-8")
    return path


def _tampered_payload(tmp_path):
    bundle = _bundle()
    bundle["payload"]["finding"]["evidence"] = "someone edited this"
    return _write(tmp_path, bundle)


def _tampered_signature(tmp_path):
    bundle = _bundle()
    value = bytearray(
        base64.b64decode(bundle["signature"]["value"].encode("ascii"))
    )
    value[0] ^= 0xFF
    bundle["signature"]["value"] = base64.b64encode(bytes(value)).decode("ascii")
    return _write(tmp_path, bundle)


def test_verify_proof_valid_prints_the_finding(tmp_path, capsys):
    bundle = _bundle()

    assert main(["verify-proof", str(_write(tmp_path, bundle))]) == 0

    out = capsys.readouterr().out
    assert "VALID" in out
    assert bundle["signature"]["fingerprint"] in out
    assert "Probe: cors" in out
    assert "Verdict: EXPOSED" in out
    assert "Target: /repo (static)" in out
    assert "INVALID" not in out


def test_verify_proof_valid_json(tmp_path, capsys):
    bundle = _bundle()

    assert main(["verify-proof", str(_write(tmp_path, bundle)), "--json"]) == 0

    data = json.loads(capsys.readouterr().out)
    assert data == {
        "status": "valid",
        "fingerprint": bundle["signature"]["fingerprint"],
        "finding": FINDING,
    }


def test_verify_proof_accepts_a_matching_fingerprint(tmp_path, capsys):
    bundle = _bundle()

    assert (
        main(
            [
                "verify-proof",
                str(_write(tmp_path, bundle)),
                "--fingerprint",
                bundle["signature"]["fingerprint"],
            ]
        )
        == 0
    )
    assert "VALID" in capsys.readouterr().out


def test_verify_proof_rejects_a_wrong_fingerprint(tmp_path, capsys):
    bundle = _bundle()

    assert (
        main(
            [
                "verify-proof",
                str(_write(tmp_path, bundle)),
                "--fingerprint",
                "sha256:" + "0" * 64,
            ]
        )
        == 1
    )
    assert "INVALID: PROOF_FINGERPRINT_MISMATCH" in capsys.readouterr().out


def test_verify_proof_rejects_a_tampered_payload(tmp_path, capsys):
    assert main(["verify-proof", str(_tampered_payload(tmp_path))]) == 1
    assert "INVALID: PROOF_MALFORMED" in capsys.readouterr().out


def test_verify_proof_rejects_a_tampered_signature(tmp_path, capsys):
    assert main(["verify-proof", str(_tampered_signature(tmp_path))]) == 1
    assert "INVALID: PROOF_SIGNATURE_INVALID" in capsys.readouterr().out


def test_verify_proof_rejects_a_missing_file(tmp_path, capsys):
    assert main(["verify-proof", str(tmp_path / "missing.json")]) == 1
    assert "INVALID: PROOF_MALFORMED" in capsys.readouterr().out


def test_verify_proof_rejects_malformed_json(tmp_path, capsys):
    path = tmp_path / "broken.json"
    path.write_text("{not json", encoding="utf-8")

    assert main(["verify-proof", str(path)]) == 1
    assert "INVALID: PROOF_MALFORMED" in capsys.readouterr().out


def test_verify_proof_json_reports_invalid(tmp_path, capsys):
    assert (
        main(["verify-proof", str(_tampered_payload(tmp_path)), "--json"]) == 1
    )

    data = json.loads(capsys.readouterr().out)
    assert data["status"] == "invalid"
    assert data["cause"] == "PROOF_MALFORMED"
    assert "bundle_id" in data["message"]


def test_verify_proof_requires_a_file():
    with pytest.raises(SystemExit) as exc:
        main(["verify-proof"])

    assert exc.value.code == 2
