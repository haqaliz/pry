"""Orchestrate ownership challenge verification and token issuance."""

import re
import secrets
from typing import Optional

from pry.own.dns import TxtResolver, default_resolve_txt, verify_dns
from pry.own.errors import BAD_CHALLENGE, UNSUPPORTED_METHOD, OwnershipError
from pry.own.target import normalize_target
from pry.own.tokens import TokenSigner
from pry.own.well_known import Fetch, default_fetch, verify_well_known

METHODS = {"dns": "dns_txt", "well-known": "well_known"}
_CHALLENGE_PATTERN = re.compile(r"^[A-Za-z0-9_-]{43}$")


def new_challenge() -> str:
    return secrets.token_urlsafe(32)


def validate_challenge(challenge: str) -> None:
    if not isinstance(challenge, str) or not _CHALLENGE_PATTERN.match(challenge):
        raise OwnershipError(BAD_CHALLENGE, "challenge must be 32 URL-safe bytes")


def verify_target(
    raw_target: str,
    method: str,
    challenge: str,
    *,
    resolve_txt: Optional[TxtResolver] = None,
    fetch: Optional[Fetch] = None,
    signer: Optional[TokenSigner] = None,
) -> str:
    target = normalize_target(raw_target)
    validate_challenge(challenge)
    if method not in METHODS:
        raise OwnershipError(UNSUPPORTED_METHOD, "unsupported method: %s" % method)

    if method == "dns":
        verify_dns(
            target,
            challenge,
            resolve_txt=default_resolve_txt if resolve_txt is None else resolve_txt,
        )
    else:
        verify_well_known(
            target, challenge, fetch=default_fetch if fetch is None else fetch
        )

    signer = TokenSigner() if signer is None else signer
    return signer.issue(target, METHODS[method])
