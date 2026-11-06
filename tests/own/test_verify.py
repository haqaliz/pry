"""Ownership verification orchestration tests."""

import re

import pytest

from pry.own.errors import (
    BAD_CHALLENGE,
    DNS_RECORD_NOT_FOUND,
    UNSUPPORTED_METHOD,
    WELL_KNOWN_MISMATCH,
    OwnershipError,
)
from pry.own.target import normalize_target
from pry.own.tokens import TokenSigner
from pry.own.verify import new_challenge, validate_challenge, verify_target
from pry.own.well_known import FetchResult

NONCE = "A" * 43
WELL_KNOWN_URL = "https://example.com/.well-known/pry-ownership.txt"


def test_new_challenge_is_43_urlsafe_characters():
    challenge = new_challenge()

    assert re.fullmatch(r"[A-Za-z0-9_-]{43}", challenge)
    assert new_challenge() != new_challenge()


def test_generated_challenge_is_valid():
    validate_challenge(new_challenge())


@pytest.mark.parametrize(
    "challenge", ["", "A" * 42, "A" * 44, "!" * 43, "A" * 43 + "\n"]
)
def test_invalid_challenges_are_rejected(challenge):
    with pytest.raises(OwnershipError) as exc:
        validate_challenge(challenge)
    assert exc.value.cause == BAD_CHALLENGE


def test_dns_verification_issues_a_valid_token(tmp_path):
    signer = TokenSigner(tmp_path / "ownership.key")
    calls = []

    def fake_resolve(name):
        calls.append(name)
        return ["pry-verify=" + NONCE]

    token = verify_target(
        "https://example.com", "dns", NONCE, resolve_txt=fake_resolve, signer=signer
    )

    assert calls == ["_pry.example.com"]
    proof = signer.validate(token, normalize_target("https://example.com"))
    assert proof.target == "https://example.com"
    assert proof.proof_type == "dns_txt"


def test_well_known_verification_issues_a_valid_token(tmp_path):
    signer = TokenSigner(tmp_path / "ownership.key")
    result = FetchResult(200, WELL_KNOWN_URL, ("pry-verify=" + NONCE).encode("ascii"))

    token = verify_target(
        "https://example.com",
        "well-known",
        NONCE,
        fetch=lambda url: result,
        signer=signer,
    )

    proof = signer.validate(token, normalize_target("https://example.com"))
    assert proof.target == "https://example.com"
    assert proof.proof_type == "well_known"


def test_default_signer_uses_pry_key_file(tmp_path, monkeypatch):
    key_path = tmp_path / "env" / "ownership.key"
    monkeypatch.setenv("PRY_KEY_FILE", str(key_path))

    token = verify_target(
        "https://example.com",
        "dns",
        NONCE,
        resolve_txt=lambda name: ["pry-verify=" + NONCE],
    )

    assert key_path.exists()
    proof = TokenSigner(key_path).validate(token, normalize_target("https://example.com"))
    assert proof.proof_type == "dns_txt"


def test_unknown_method_is_rejected(tmp_path):
    signer = TokenSigner(tmp_path / "ownership.key")

    with pytest.raises(OwnershipError) as exc:
        verify_target("https://example.com", "oauth", NONCE, signer=signer)
    assert exc.value.cause == UNSUPPORTED_METHOD


def test_invalid_challenge_is_rejected_before_dispatch(tmp_path):
    signer = TokenSigner(tmp_path / "ownership.key")

    def fail_resolve(name):
        raise AssertionError("resolver must not run for a bad challenge")

    with pytest.raises(OwnershipError) as exc:
        verify_target(
            "https://example.com", "dns", "short", resolve_txt=fail_resolve, signer=signer
        )
    assert exc.value.cause == BAD_CHALLENGE


def test_dns_failure_propagates_its_cause(tmp_path):
    signer = TokenSigner(tmp_path / "ownership.key")

    with pytest.raises(OwnershipError) as exc:
        verify_target(
            "https://example.com", "dns", NONCE, resolve_txt=lambda name: [], signer=signer
        )
    assert exc.value.cause == DNS_RECORD_NOT_FOUND


def test_well_known_failure_propagates_its_cause(tmp_path):
    signer = TokenSigner(tmp_path / "ownership.key")
    result = FetchResult(200, WELL_KNOWN_URL, b"pry-verify=" + b"B" * 43)

    with pytest.raises(OwnershipError) as exc:
        verify_target(
            "https://example.com",
            "well-known",
            NONCE,
            fetch=lambda url: result,
            signer=signer,
        )
    assert exc.value.cause == WELL_KNOWN_MISMATCH
