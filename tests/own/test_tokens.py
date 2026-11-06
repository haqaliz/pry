"""Signed ownership token tests (AT7/AT8)."""

import base64
import os
import stat

import pytest

from pry.own.errors import (
    KEY_INVALID,
    TOKEN_BAD_SIGNATURE,
    TOKEN_EXPIRED,
    TOKEN_MALFORMED,
    TOKEN_TARGET_MISMATCH,
    OwnershipError,
)
from pry.own.target import normalize_target
from pry.own.tokens import OwnershipToken, TokenSigner

DAY = 24 * 60 * 60


def test_issue_and_validate_round_trip(tmp_path):
    signer = TokenSigner(tmp_path / "ownership.key")
    target = normalize_target("https://example.com")

    token = signer.issue(target, "dns_txt", now=1_000)

    proof = signer.validate(token, target, now=1_000)
    assert proof == OwnershipToken(
        target="https://example.com",
        proof_type="dns_txt",
        issued_at=1_000,
        expires_at=1_000 + DAY,
    )


def test_token_format_and_canonical_payload(tmp_path):
    signer = TokenSigner(tmp_path / "ownership.key")
    target = normalize_target("https://EXAMPLE.com:443/app?q=1")

    token = signer.issue(target, "well_known", now=0)

    version, payload, signature = token.split(".")
    assert version == "pry1"
    raw = base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4))
    assert raw == (
        b'{"exp":86400,"iat":0,"proof":"well_known",'
        b'"target":"https://example.com","v":1}'
    )
    assert len(base64.urlsafe_b64decode(signature + "=" * (-len(signature) % 4))) == 32


def test_key_file_created_with_secure_permissions(tmp_path):
    key_path = tmp_path / "nested" / "ownership.key"

    TokenSigner(key_path)

    assert key_path.exists()
    assert len(key_path.read_bytes()) == 32
    assert stat.S_IMODE(os.stat(key_path).st_mode) == 0o600
    assert stat.S_IMODE(os.stat(key_path.parent).st_mode) == 0o700


def test_second_signer_reads_the_existing_key(tmp_path):
    key_path = tmp_path / "ownership.key"
    first = TokenSigner(key_path)
    key_bytes = key_path.read_bytes()
    target = normalize_target("https://example.com")
    token = first.issue(target, "dns_txt", now=100)

    second = TokenSigner(key_path)

    assert key_path.read_bytes() == key_bytes
    assert second.validate(token, target, now=100).target == target.origin


def test_pry_key_file_env_override(tmp_path, monkeypatch):
    key_path = tmp_path / "env" / "ownership.key"
    monkeypatch.setenv("PRY_KEY_FILE", str(key_path))

    signer = TokenSigner()
    target = normalize_target("https://example.com")
    token = signer.issue(target, "dns_txt", now=0)

    assert key_path.exists()
    assert signer.validate(token, target, now=0).proof_type == "dns_txt"


def _replace_char(value, index):
    replacement = "A" if value[index] != "A" else "B"
    return value[:index] + replacement + value[index + 1:]


def test_any_tampered_signature_character_is_rejected(tmp_path):
    signer = TokenSigner(tmp_path / "ownership.key")
    target = normalize_target("https://example.com")
    version, payload, signature = signer.issue(target, "dns_txt", now=0).split(".")

    for index in range(len(signature)):
        tampered = ".".join((version, payload, _replace_char(signature, index)))
        with pytest.raises(OwnershipError) as exc:
            signer.validate(tampered, target, now=0)
        assert exc.value.cause == TOKEN_BAD_SIGNATURE


def test_any_tampered_payload_character_is_rejected(tmp_path):
    signer = TokenSigner(tmp_path / "ownership.key")
    target = normalize_target("https://example.com")
    version, payload, signature = signer.issue(target, "dns_txt", now=0).split(".")

    for index in range(len(payload)):
        tampered = ".".join((version, _replace_char(payload, index), signature))
        with pytest.raises(OwnershipError) as exc:
            signer.validate(tampered, target, now=0)
        assert exc.value.cause == TOKEN_BAD_SIGNATURE


def test_non_canonical_signature_encoding_is_rejected(tmp_path):
    signer = TokenSigner(tmp_path / "ownership.key")
    target = normalize_target("https://example.com")
    version, payload, signature = signer.issue(target, "dns_txt", now=0).split(".")
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    non_canonical = signature[:-1] + alphabet[alphabet.index(signature[-1]) + 1]

    with pytest.raises(OwnershipError) as exc:
        signer.validate(".".join((version, payload, non_canonical)), target, now=0)
    assert exc.value.cause == TOKEN_BAD_SIGNATURE


@pytest.mark.parametrize("now", [DAY, DAY + 1])
def test_expired_token_is_rejected(tmp_path, now):
    signer = TokenSigner(tmp_path / "ownership.key")
    target = normalize_target("https://example.com")
    token = signer.issue(target, "dns_txt", now=0)

    with pytest.raises(OwnershipError) as exc:
        signer.validate(token, target, now=now)
    assert exc.value.cause == TOKEN_EXPIRED


def test_wrong_target_is_rejected(tmp_path):
    signer = TokenSigner(tmp_path / "ownership.key")
    token = signer.issue(normalize_target("https://example.com"), "dns_txt", now=0)

    with pytest.raises(OwnershipError) as exc:
        signer.validate(token, normalize_target("https://other.example"), now=0)
    assert exc.value.cause == TOKEN_TARGET_MISMATCH


def test_token_from_another_key_is_rejected(tmp_path):
    first = TokenSigner(tmp_path / "one.key")
    second = TokenSigner(tmp_path / "two.key")
    target = normalize_target("https://example.com")
    token = first.issue(target, "dns_txt", now=0)

    with pytest.raises(OwnershipError) as exc:
        second.validate(token, target, now=0)
    assert exc.value.cause == TOKEN_BAD_SIGNATURE


@pytest.mark.parametrize("token", ["garbage", "pry1.a.b", "pry1", "pry1..", "pry1.a.b.c"])
def test_malformed_tokens_are_rejected(tmp_path, token):
    signer = TokenSigner(tmp_path / "ownership.key")

    with pytest.raises(OwnershipError) as exc:
        signer.validate(token, normalize_target("https://example.com"), now=0)
    assert exc.value.cause == TOKEN_MALFORMED


def test_wrong_version_prefix_is_malformed(tmp_path):
    signer = TokenSigner(tmp_path / "ownership.key")
    target = normalize_target("https://example.com")
    token = signer.issue(target, "dns_txt", now=0)

    with pytest.raises(OwnershipError) as exc:
        signer.validate("pry2" + token[4:], target, now=0)
    assert exc.value.cause == TOKEN_MALFORMED


def test_wrong_size_key_is_invalid_and_not_regenerated(tmp_path):
    key_path = tmp_path / "ownership.key"
    key_path.write_bytes(b"x" * 16)

    with pytest.raises(OwnershipError) as exc:
        TokenSigner(key_path)

    assert exc.value.cause == KEY_INVALID
    assert key_path.read_bytes() == b"x" * 16
