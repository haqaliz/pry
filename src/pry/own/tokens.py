"""Signed, target-bound ownership tokens."""

import base64
import binascii
import hashlib
import hmac
import json
import os
import secrets
import time
from dataclasses import dataclass
from typing import Optional, Union

from pry.own.errors import (
    KEY_INVALID,
    TOKEN_BAD_SIGNATURE,
    TOKEN_EXPIRED,
    TOKEN_MALFORMED,
    TOKEN_TARGET_MISMATCH,
    OwnershipError,
)
from pry.own.target import Target

_PREFIX = "pry1"
_KEY_BYTES = 32
_TTL = 24 * 60 * 60


@dataclass(frozen=True)
class OwnershipToken:
    target: str
    proof_type: str
    issued_at: int
    expires_at: int


def _b64encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _b64decode(value: str) -> bytes:
    padded = value + "=" * (-len(value) % 4)
    return base64.b64decode(padded, altchars=b"-_", validate=True)


class TokenSigner:
    """Issues and validates HMAC tokens with a local key file."""

    def __init__(self, key_path: Optional[Union[str, os.PathLike]] = None) -> None:
        if key_path is None:
            key_path = os.environ.get("PRY_KEY_FILE") or os.path.expanduser(
                "~/.pry/ownership.key"
            )
        self.key_path = os.fspath(key_path)
        self._key = self._load_or_create_key()

    def _load_or_create_key(self) -> bytes:
        directory = os.path.dirname(self.key_path) or "."
        try:
            os.makedirs(directory, mode=0o700, exist_ok=True)
        except OSError as exc:
            raise OwnershipError(
                KEY_INVALID, "cannot create key directory: %s" % exc
            ) from exc

        try:
            fd = os.open(self.key_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError:
            return self._read_key()
        except OSError as exc:
            raise OwnershipError(KEY_INVALID, "cannot create key file: %s" % exc) from exc

        key = secrets.token_bytes(_KEY_BYTES)
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(key)
            os.chmod(self.key_path, 0o600)
        except OSError as exc:
            raise OwnershipError(KEY_INVALID, "cannot write key file: %s" % exc) from exc
        return key

    def _read_key(self) -> bytes:
        try:
            with open(self.key_path, "rb") as handle:
                key = handle.read()
        except OSError as exc:
            raise OwnershipError(KEY_INVALID, "cannot read key file: %s" % exc) from exc
        if len(key) != _KEY_BYTES:
            raise OwnershipError(KEY_INVALID, "key file must contain 32 bytes")
        return key

    def issue(self, target: Target, proof_type: str, now: Optional[int] = None) -> str:
        issued_at = int(time.time()) if now is None else int(now)
        payload = json.dumps(
            {
                "v": 1,
                "target": target.origin,
                "proof": proof_type,
                "iat": issued_at,
                "exp": issued_at + _TTL,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        signature = hmac.new(self._key, payload, hashlib.sha256).digest()
        return "%s.%s.%s" % (_PREFIX, _b64encode(payload), _b64encode(signature))

    def validate(
        self, token: str, target: Target, now: Optional[int] = None
    ) -> OwnershipToken:
        version, payload, signature = self._split(token)
        if version != _PREFIX:
            raise OwnershipError(TOKEN_MALFORMED, "token prefix is not pry1")
        if not payload or not signature:
            raise OwnershipError(TOKEN_MALFORMED, "token parts must not be empty")

        try:
            payload_bytes = _b64decode(payload)
        except (TypeError, ValueError, binascii.Error) as exc:
            raise OwnershipError(
                TOKEN_MALFORMED, "token payload is not valid base64url"
            ) from exc
        if _b64encode(payload_bytes) != payload:
            raise OwnershipError(
                TOKEN_BAD_SIGNATURE, "token payload encoding is not canonical"
            )

        try:
            signature_bytes = _b64decode(signature)
        except (TypeError, ValueError, binascii.Error) as exc:
            raise OwnershipError(
                TOKEN_BAD_SIGNATURE, "token signature is not valid base64url"
            ) from exc
        if (
            len(signature_bytes) != hashlib.sha256().digest_size
            or _b64encode(signature_bytes) != signature
        ):
            raise OwnershipError(TOKEN_BAD_SIGNATURE, "token signature is malformed")

        expected = hmac.new(self._key, payload_bytes, hashlib.sha256).digest()
        if not hmac.compare_digest(expected, signature_bytes):
            raise OwnershipError(TOKEN_BAD_SIGNATURE, "token signature does not verify")

        data = self._parse(payload_bytes)
        if data.get("v") != 1:
            raise OwnershipError(TOKEN_MALFORMED, "unsupported token version")

        try:
            target_origin = data["target"]
            proof_type = data["proof"]
            issued_at = data["iat"]
            expires_at = data["exp"]
        except KeyError as exc:
            raise OwnershipError(
                TOKEN_MALFORMED, "token payload is missing %s" % exc
            ) from exc
        if (
            not isinstance(target_origin, str)
            or not isinstance(proof_type, str)
            or type(issued_at) is not int
            or type(expires_at) is not int
        ):
            raise OwnershipError(TOKEN_MALFORMED, "token payload has invalid fields")
        if expires_at <= issued_at:
            raise OwnershipError(TOKEN_MALFORMED, "token expiry is not after issue")
        if target_origin != target.origin:
            raise OwnershipError(TOKEN_TARGET_MISMATCH, "token is bound to another target")

        current = int(time.time()) if now is None else int(now)
        if current >= expires_at:
            raise OwnershipError(TOKEN_EXPIRED, "token has expired")

        return OwnershipToken(
            target=target_origin,
            proof_type=proof_type,
            issued_at=issued_at,
            expires_at=expires_at,
        )

    @staticmethod
    def _split(token: str):
        if not isinstance(token, str):
            raise OwnershipError(TOKEN_MALFORMED, "token must be a string")
        parts = token.split(".")
        if len(parts) != 3:
            raise OwnershipError(TOKEN_MALFORMED, "token must have three parts")
        return parts

    @staticmethod
    def _parse(payload: bytes):
        try:
            data = json.loads(payload.decode("utf-8"))
        except (UnicodeDecodeError, ValueError) as exc:
            raise OwnershipError(TOKEN_MALFORMED, "token payload is not JSON") from exc
        if not isinstance(data, dict):
            raise OwnershipError(TOKEN_MALFORMED, "token payload must be an object")
        return data
