"""Ed25519 proof bundle tests (AT1-AT7, AT10).

Everything here is offline: keys live in tmp_path, bundles are built in
memory, and nothing touches the network or the user's home directory.
"""

import base64
import copy
import hashlib
import json
import shutil
import stat

import pytest

from pry.proof import (
    PROOF_FINGERPRINT_MISMATCH,
    PROOF_KEY_INVALID,
    PROOF_MALFORMED,
    PROOF_SIGNATURE_INVALID,
    ProofError,
    ProofSigner,
    build_bundle,
    canonical_bytes,
    load_bundle,
    public_fingerprint,
    verify_bundle,
    write_bundle,
)

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

CREATED_AT = "2026-11-08T00:00:00Z"


@pytest.fixture(autouse=True)
def proof_key(tmp_path, monkeypatch):
    path = tmp_path / "proof.key"
    monkeypatch.setenv("PRY_PROOF_KEY", str(path))
    return path


def _mode(path):
    return stat.S_IMODE(path.stat().st_mode)


def _bundle(**kwargs):
    options = {"created_at": CREATED_AT}
    options.update(kwargs)
    return build_bundle(
        copy.deepcopy(TARGET), copy.deepcopy(FINDING), **options
    )


def _decode(value):
    return base64.b64decode(value.encode("ascii"), validate=True)


def test_bundle_has_the_contract_fields_and_verifies():
    bundle = _bundle()

    assert set(bundle) == {
        "version",
        "created_at",
        "bundle_id",
        "payload",
        "signature",
    }
    assert bundle["version"] == 1
    assert bundle["created_at"] == CREATED_AT
    assert bundle["payload"] == {"target": TARGET, "finding": FINDING}

    signature = bundle["signature"]
    assert set(signature) == {"alg", "public_key", "fingerprint", "value"}
    assert signature["alg"] == "Ed25519"
    public_key = _decode(signature["public_key"])
    assert len(public_key) == 32
    assert signature["fingerprint"] == public_fingerprint(public_key)
    assert signature["fingerprint"].startswith("sha256:")
    assert len(_decode(signature["value"])) == 64

    payload, fingerprint = verify_bundle(bundle)
    assert payload == bundle["payload"]
    assert fingerprint == signature["fingerprint"]


def test_bundle_id_is_the_sha256_of_the_canonical_payload():
    bundle = _bundle()

    expected = hashlib.sha256(canonical_bytes(bundle["payload"])).hexdigest()
    assert bundle["bundle_id"] == expected
    assert len(bundle["bundle_id"]) == 64
    assert bundle["bundle_id"] == bundle["bundle_id"].lower()


def test_canonical_bytes_sorts_keys_and_has_no_whitespace():
    value = {"b": 1, "a": "two"}

    assert canonical_bytes(value) == b'{"a":"two","b":1}'
    assert canonical_bytes(value).decode("utf-8") == '{"a":"two","b":1}'


def test_bundle_id_ignores_dict_order_and_changes_with_values():
    first = _bundle()
    second = build_bundle(
        dict(reversed(list(TARGET.items()))),
        dict(reversed(list(FINDING.items()))),
        created_at=CREATED_AT,
    )
    assert first["bundle_id"] == second["bundle_id"]

    third = build_bundle(dict(TARGET, kind="node"), FINDING, created_at=CREATED_AT)
    assert third["bundle_id"] != first["bundle_id"]


def test_bundle_contains_no_private_key(proof_key):
    text = json.dumps(_bundle())
    seed = proof_key.read_bytes()

    assert len(seed) == 32
    assert seed.hex() not in text
    assert base64.b64encode(seed).decode("ascii") not in text
    assert "private" not in text.lower()


def test_tampered_payload_is_rejected():
    bundle = _bundle()
    bundle["payload"]["finding"]["evidence"] = "someone edited this"

    with pytest.raises(ProofError) as exc:
        verify_bundle(bundle)

    assert exc.value.cause == PROOF_MALFORMED


def test_tampered_payload_with_a_recomputed_id_fails_the_signature():
    bundle = _bundle()
    bundle["payload"]["finding"]["evidence"] = "someone edited this"
    bundle["bundle_id"] = hashlib.sha256(
        canonical_bytes(bundle["payload"])
    ).hexdigest()

    with pytest.raises(ProofError) as exc:
        verify_bundle(bundle)

    assert exc.value.cause == PROOF_SIGNATURE_INVALID


def test_tampered_signature_is_rejected():
    bundle = _bundle()
    value = bytearray(_decode(bundle["signature"]["value"]))
    value[0] ^= 0xFF
    bundle["signature"]["value"] = base64.b64encode(bytes(value)).decode("ascii")

    with pytest.raises(ProofError) as exc:
        verify_bundle(bundle)

    assert exc.value.cause == PROOF_SIGNATURE_INVALID


def test_swapped_public_key_is_rejected_by_the_embedded_fingerprint(tmp_path):
    bundle = _bundle()
    other = build_bundle(
        TARGET, FINDING, signer=ProofSigner(tmp_path / "other.key")
    )
    bundle["signature"]["public_key"] = other["signature"]["public_key"]

    with pytest.raises(ProofError) as exc:
        verify_bundle(bundle)

    assert exc.value.cause == PROOF_FINGERPRINT_MISMATCH


def test_swapped_public_key_and_fingerprint_fail_the_signature(tmp_path):
    bundle = _bundle()
    other = build_bundle(
        TARGET, FINDING, signer=ProofSigner(tmp_path / "other.key")
    )
    bundle["signature"]["public_key"] = other["signature"]["public_key"]
    bundle["signature"]["fingerprint"] = other["signature"]["fingerprint"]

    with pytest.raises(ProofError) as exc:
        verify_bundle(bundle)

    assert exc.value.cause == PROOF_SIGNATURE_INVALID


def test_expected_fingerprint_must_match():
    bundle = _bundle()
    fingerprint = bundle["signature"]["fingerprint"]

    assert verify_bundle(bundle, expected_fingerprint=fingerprint)[1] == fingerprint

    with pytest.raises(ProofError) as exc:
        verify_bundle(bundle, expected_fingerprint="sha256:" + "0" * 64)

    assert exc.value.cause == PROOF_FINGERPRINT_MISMATCH


def _mutations():
    def missing_top_level(bundle):
        del bundle["version"]

    def missing_signature_field(bundle):
        del bundle["signature"]["value"]

    def bad_version(bundle):
        bundle["version"] = 2

    def bad_algorithm(bundle):
        bundle["signature"]["alg"] = "HMAC"

    def bad_public_key_base64(bundle):
        bundle["signature"]["public_key"] = "not base64!"

    def short_public_key(bundle):
        bundle["signature"]["public_key"] = base64.b64encode(b"short").decode(
            "ascii"
        )

    def bad_signature_base64(bundle):
        bundle["signature"]["value"] = "!!!"

    def short_signature(bundle):
        bundle["signature"]["value"] = base64.b64encode(b"short").decode("ascii")

    def payload_not_an_object(bundle):
        bundle["payload"] = []

    def payload_missing_finding(bundle):
        del bundle["payload"]["finding"]

    def bad_bundle_id(bundle):
        bundle["bundle_id"] = "../../escape"

    def bad_created_at(bundle):
        bundle["created_at"] = 7

    def bad_signature_block(bundle):
        bundle["signature"] = "nope"

    return [
        ("missing top-level field", missing_top_level),
        ("missing signature field", missing_signature_field),
        ("unsupported version", bad_version),
        ("unsupported algorithm", bad_algorithm),
        ("invalid public key base64", bad_public_key_base64),
        ("short public key", short_public_key),
        ("invalid signature base64", bad_signature_base64),
        ("short signature", short_signature),
        ("payload is not an object", payload_not_an_object),
        ("payload has no finding", payload_missing_finding),
        ("bundle id is not hex", bad_bundle_id),
        ("created_at is not a string", bad_created_at),
        ("signature block is not an object", bad_signature_block),
    ]


@pytest.mark.parametrize("description,mutate", _mutations())
def test_malformed_bundles_are_rejected(description, mutate):
    bundle = _bundle()
    mutate(bundle)

    with pytest.raises(ProofError) as exc:
        verify_bundle(bundle)

    assert exc.value.cause == PROOF_MALFORMED, description


@pytest.mark.parametrize("bundle", [[], "bundle", None, 3])
def test_a_bundle_must_be_an_object(bundle):
    with pytest.raises(ProofError) as exc:
        verify_bundle(bundle)

    assert exc.value.cause == PROOF_MALFORMED


def test_load_bundle_reads_json_and_rejects_missing_or_broken_files(tmp_path):
    bundle = _bundle()
    path = tmp_path / "bundle.json"
    path.write_text(json.dumps(bundle), encoding="utf-8")
    assert load_bundle(path) == bundle

    with pytest.raises(ProofError) as exc:
        load_bundle(tmp_path / "missing.json")
    assert exc.value.cause == PROOF_MALFORMED

    broken = tmp_path / "broken.json"
    broken.write_text("{not json", encoding="utf-8")
    with pytest.raises(ProofError) as exc:
        load_bundle(broken)
    assert exc.value.cause == PROOF_MALFORMED

    array = tmp_path / "array.json"
    array.write_text("[]", encoding="utf-8")
    with pytest.raises(ProofError) as exc:
        load_bundle(array)
    assert exc.value.cause == PROOF_MALFORMED


def test_key_file_is_32_bytes_at_0600_inside_a_0700_directory(tmp_path):
    key_dir = tmp_path / "keys"
    key_path = key_dir / "proof.key"

    signer = ProofSigner(key_path=key_path)

    assert signer.key_path == str(key_path)
    assert len(key_path.read_bytes()) == 32
    assert _mode(key_path) == 0o600
    assert _mode(key_dir) == 0o700


@pytest.mark.parametrize("size", [0, 31, 33])
def test_a_wrong_size_key_is_rejected_and_never_regenerated(tmp_path, size):
    key_path = tmp_path / "proof.key"
    original = b"x" * size
    key_path.write_bytes(original)

    with pytest.raises(ProofError) as exc:
        ProofSigner(key_path=key_path)

    assert exc.value.cause == PROOF_KEY_INVALID
    assert key_path.read_bytes() == original


def test_the_env_override_selects_the_key_path(proof_key):
    signer = ProofSigner()

    assert signer.key_path == str(proof_key)
    assert proof_key.is_file()


def test_two_signers_produce_different_fingerprints(tmp_path):
    first = ProofSigner()
    second = ProofSigner(tmp_path / "other.key")

    first_bundle = build_bundle(TARGET, FINDING, signer=first)
    second_bundle = build_bundle(TARGET, FINDING, signer=second)

    assert (
        first_bundle["signature"]["fingerprint"]
        != second_bundle["signature"]["fingerprint"]
    )


def test_write_bundle_is_a_0600_atomic_file_under_proofs(tmp_path):
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    bundle = _bundle()

    path = write_bundle(run_dir, bundle)

    assert path == run_dir / "proofs" / (bundle["bundle_id"] + ".json")
    assert _mode(path) == 0o600
    assert not (path.parent / (path.name + ".tmp")).exists()
    assert load_bundle(path) == bundle
    assert verify_bundle(load_bundle(path))[1] == bundle["signature"]["fingerprint"]


def test_a_copied_bundle_verifies_without_the_run_directory(tmp_path):
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    path = write_bundle(run_dir, _bundle())
    copied = tmp_path / "copied.json"
    shutil.copyfile(str(path), str(copied))
    shutil.rmtree(str(run_dir))

    payload, fingerprint = verify_bundle(load_bundle(copied))

    assert payload["finding"]["probe"] == "cors"
    assert fingerprint.startswith("sha256:")
