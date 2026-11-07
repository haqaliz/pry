"""Ed25519 proof bundles: local keys, canonical payloads, and verification."""

import base64
import binascii
import hashlib
import json
import os
import re
import secrets
from pathlib import Path
from typing import Optional, Tuple, Union

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from pry.intake.snapshot import utc_now

PROOF_VERSION = 1
PROOF_FAILED = "PROOF_FAILED"
PROOF_KEY_INVALID = "PROOF_KEY_INVALID"
PROOF_MALFORMED = "PROOF_MALFORMED"
PROOF_FINGERPRINT_MISMATCH = "PROOF_FINGERPRINT_MISMATCH"
PROOF_SIGNATURE_INVALID = "PROOF_SIGNATURE_INVALID"

KEY_ENV = "PRY_PROOF_KEY"
DEFAULT_KEY_PATH = "~/.pry/proof.key"
PROOFS_DIR = "proofs"

_KEY_BYTES = 32
_SIGNATURE_BYTES = 64
_PUBLIC_KEY_BYTES = 32
_BUNDLE_ID = re.compile(r"^[0-9a-f]{64}$")


class ProofError(Exception):
    """A proof failure with a stable, machine-readable cause."""

    def __init__(self, cause: str, message: str) -> None:
        super().__init__(message)
        self.cause = cause
        self.message = message

    def __str__(self) -> str:
        return "%s: %s" % (self.cause, self.message)


def canonical_bytes(payload) -> bytes:
    """Sorted JSON with no whitespace, encoded as UTF-8 bytes."""
    try:
        text = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    except (TypeError, ValueError) as exc:
        raise ProofError(
            PROOF_FAILED, "cannot encode payload as JSON: %s" % exc
        ) from exc
    return text.encode("utf-8")


def public_fingerprint(public_key) -> str:
    """Return ``sha256:<hex>`` over the raw public key bytes."""
    return "sha256:" + hashlib.sha256(bytes(public_key)).hexdigest()


def _decode(value: str, name: str) -> bytes:
    try:
        return base64.b64decode(value.encode("ascii"), validate=True)
    except (UnicodeEncodeError, ValueError, binascii.Error) as exc:
        raise ProofError(
            PROOF_MALFORMED, "%s is not valid base64" % name
        ) from exc


def _malformed(message: str) -> ProofError:
    return ProofError(PROOF_MALFORMED, message)


class ProofSigner:
    """Loads or creates a local Ed25519 seed and signs payloads."""

    def __init__(
        self,
        key_path: Optional[Union[str, os.PathLike]] = None,
        created_at: Optional[str] = None,
    ) -> None:
        if key_path is None:
            key_path = os.environ.get(KEY_ENV) or DEFAULT_KEY_PATH
        self.key_path = os.path.expanduser(os.fspath(key_path))
        self.created_at = created_at
        private_key = Ed25519PrivateKey.from_private_bytes(
            self._load_or_create_key()
        )
        self.public_key = private_key.public_key().public_bytes(
            Encoding.Raw, PublicFormat.Raw
        )
        self.fingerprint = public_fingerprint(self.public_key)
        self._private_key = private_key

    def _load_or_create_key(self) -> bytes:
        directory = os.path.dirname(self.key_path) or "."
        try:
            os.makedirs(directory, mode=0o700, exist_ok=True)
        except OSError as exc:
            raise ProofError(
                PROOF_KEY_INVALID, "cannot create key directory: %s" % exc
            ) from exc

        try:
            fd = os.open(
                self.key_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600
            )
        except FileExistsError:
            return self._read_key()
        except OSError as exc:
            raise ProofError(
                PROOF_KEY_INVALID, "cannot create key file: %s" % exc
            ) from exc

        key = secrets.token_bytes(_KEY_BYTES)
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(key)
            os.chmod(self.key_path, 0o600)
        except OSError as exc:
            raise ProofError(
                PROOF_KEY_INVALID, "cannot write key file: %s" % exc
            ) from exc
        return key

    def _read_key(self) -> bytes:
        try:
            with open(self.key_path, "rb") as handle:
                key = handle.read()
        except OSError as exc:
            raise ProofError(
                PROOF_KEY_INVALID, "cannot read key file: %s" % exc
            ) from exc
        if len(key) != _KEY_BYTES:
            raise ProofError(
                PROOF_KEY_INVALID,
                "key file must contain exactly %d bytes" % _KEY_BYTES,
            )
        return key

    def sign(self, payload) -> dict:
        try:
            value = self._private_key.sign(canonical_bytes(payload))
        except (TypeError, ValueError) as exc:
            raise ProofError(PROOF_FAILED, "cannot sign payload: %s" % exc) from exc
        return {
            "alg": "Ed25519",
            "public_key": base64.b64encode(self.public_key).decode("ascii"),
            "fingerprint": self.fingerprint,
            "value": base64.b64encode(value).decode("ascii"),
        }


def build_bundle(
    target, finding, signer: Optional[ProofSigner] = None, created_at=None
) -> dict:
    """Build a signed bundle for one finding against one target snapshot."""
    signer = ProofSigner() if signer is None else signer
    payload = {"target": target, "finding": finding}
    payload_bytes = canonical_bytes(payload)
    if created_at is None:
        created_at = signer.created_at
    if created_at is None:
        created_at = utc_now()
    return {
        "version": PROOF_VERSION,
        "created_at": created_at,
        "bundle_id": hashlib.sha256(payload_bytes).hexdigest(),
        "payload": payload,
        "signature": signer.sign(payload),
    }


def write_bundle(run_dir, bundle) -> Path:
    """Atomically write ``proofs/<bundle_id>.json`` at 0600."""
    bundle_id = bundle.get("bundle_id") if isinstance(bundle, dict) else None
    if not isinstance(bundle_id, str) or not _BUNDLE_ID.fullmatch(bundle_id):
        raise _malformed("bundle_id must be 64 lowercase hex characters")

    proofs = Path(run_dir) / PROOFS_DIR
    target = proofs / (bundle_id + ".json")
    temp = proofs / (bundle_id + ".json.tmp")
    try:
        proofs.mkdir(mode=0o700, parents=True, exist_ok=True)
        payload = json.dumps(bundle, sort_keys=True, indent=2) + "\n"
        temp.write_text(payload, encoding="utf-8")
        os.chmod(str(temp), 0o600)
        os.replace(str(temp), str(target))
    except (OSError, TypeError, ValueError) as exc:
        try:
            temp.unlink()
        except OSError:
            pass
        raise ProofError(
            PROOF_FAILED, "cannot write bundle: %s" % exc
        ) from exc
    return target


def load_bundle(path) -> dict:
    """Read a bundle file; shape validation belongs to verify_bundle."""
    try:
        text = Path(path).read_text(encoding="utf-8")
    except OSError as exc:
        raise ProofError(
            PROOF_MALFORMED, "cannot read bundle: %s" % exc
        ) from exc
    try:
        bundle = json.loads(text)
    except ValueError as exc:
        raise ProofError(PROOF_MALFORMED, "bundle is not valid JSON") from exc
    if not isinstance(bundle, dict):
        raise _malformed("bundle must be a JSON object")
    return bundle


def verify_bundle(
    bundle, expected_fingerprint: Optional[str] = None
) -> Tuple[dict, str]:
    """Validate shape, fingerprint, payload hash, and signature."""
    if not isinstance(bundle, dict):
        raise _malformed("bundle must be a JSON object")

    try:
        version = bundle["version"]
        created_at = bundle["created_at"]
        bundle_id = bundle["bundle_id"]
        payload = bundle["payload"]
        signature = bundle["signature"]
    except KeyError as exc:
        raise _malformed("bundle is missing %s" % exc) from exc

    if type(version) is not int or version != PROOF_VERSION:
        raise _malformed("unsupported bundle version")
    if not isinstance(created_at, str) or not created_at:
        raise _malformed("created_at must be a non-empty string")
    if not isinstance(payload, dict):
        raise _malformed("payload must be an object")
    if not isinstance(payload.get("target"), dict):
        raise _malformed("payload must contain a target object")
    if not isinstance(payload.get("finding"), dict):
        raise _malformed("payload must contain a finding object")
    if not isinstance(signature, dict):
        raise _malformed("signature must be an object")

    try:
        alg = signature["alg"]
        public_key_b64 = signature["public_key"]
        declared_fingerprint = signature["fingerprint"]
        signature_b64 = signature["value"]
    except KeyError as exc:
        raise _malformed("signature is missing %s" % exc) from exc

    if alg != "Ed25519":
        raise _malformed("unsupported signature algorithm")
    if not isinstance(public_key_b64, str):
        raise _malformed("public key must be a string")
    if not isinstance(declared_fingerprint, str):
        raise _malformed("fingerprint must be a string")
    if not isinstance(signature_b64, str):
        raise _malformed("signature value must be a string")

    public_key = _decode(public_key_b64, "public key")
    if len(public_key) != _PUBLIC_KEY_BYTES:
        raise _malformed("public key must be 32 bytes")
    fingerprint = public_fingerprint(public_key)
    if declared_fingerprint != fingerprint:
        raise ProofError(
            PROOF_FINGERPRINT_MISMATCH,
            "embedded fingerprint does not match the public key",
        )
    if (
        expected_fingerprint is not None
        and expected_fingerprint != fingerprint
    ):
        raise ProofError(
            PROOF_FINGERPRINT_MISMATCH,
            "fingerprint does not match the expected value",
        )

    if not isinstance(bundle_id, str) or not _BUNDLE_ID.fullmatch(bundle_id):
        raise _malformed("bundle_id must be 64 lowercase hex characters")
    payload_bytes = canonical_bytes(payload)
    if hashlib.sha256(payload_bytes).hexdigest() != bundle_id:
        raise _malformed("bundle_id does not match the payload")

    signature_bytes = _decode(signature_b64, "signature")
    if len(signature_bytes) != _SIGNATURE_BYTES:
        raise _malformed("signature must be 64 bytes")

    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(
            signature_bytes, payload_bytes
        )
    except InvalidSignature as exc:
        raise ProofError(
            PROOF_SIGNATURE_INVALID, "signature does not verify"
        ) from exc

    return payload, fingerprint
