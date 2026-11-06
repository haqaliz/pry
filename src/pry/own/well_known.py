"""Well-known file ownership verification."""

import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Callable, Optional, Tuple
from urllib.parse import urljoin, urlsplit

from pry.own.errors import (
    INSECURE_TRANSPORT,
    WELL_KNOWN_ERROR,
    WELL_KNOWN_MISMATCH,
    WELL_KNOWN_NOT_FOUND,
    WELL_KNOWN_REDIRECT,
    OwnershipError,
)
from pry.own.target import Target

_MAX_BODY = 4096
_FETCH_LIMIT = _MAX_BODY + 1


@dataclass(frozen=True)
class FetchResult:
    status: int
    final_url: str
    body: bytes


Fetch = Callable[[str], FetchResult]


def _origin(url: str) -> Optional[Tuple[str, str, int]]:
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError:
        return None
    scheme = parts.scheme.lower()
    if port is None:
        if scheme == "https":
            port = 443
        elif scheme == "http":
            port = 80
    return scheme, (parts.hostname or "").lower(), port


class _OriginBoundRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if _origin(urljoin(req.full_url, newurl)) != _origin(req.full_url):
            raise OwnershipError(
                WELL_KNOWN_REDIRECT, "well-known redirect left the target origin"
            )
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def default_fetch(url: str) -> FetchResult:
    opener = urllib.request.build_opener(_OriginBoundRedirectHandler)
    request = urllib.request.Request(url)
    try:
        response = opener.open(request, timeout=5.0)
    except urllib.error.HTTPError as exc:
        return FetchResult(exc.code, getattr(exc, "url", url), b"")
    except OwnershipError:
        raise
    except Exception as exc:
        raise OwnershipError(WELL_KNOWN_ERROR, "well-known fetch failed: %s" % exc) from exc

    try:
        body = response.read(_FETCH_LIMIT)
        return FetchResult(response.status, response.geturl(), body)
    finally:
        response.close()


def verify_well_known(
    target: Target,
    challenge: str,
    fetch: Fetch = default_fetch,
) -> None:
    if target.scheme != "https" and not target.is_loopback:
        raise OwnershipError(
            INSECURE_TRANSPORT, "well-known verification requires HTTPS"
        )

    url = target.well_known_url
    try:
        result = fetch(url)
    except OwnershipError:
        raise
    except Exception as exc:
        raise OwnershipError(WELL_KNOWN_ERROR, "well-known fetch failed: %s" % exc) from exc

    if _origin(result.final_url) != _origin(url):
        raise OwnershipError(
            WELL_KNOWN_REDIRECT, "well-known fetch left the target origin"
        )
    if result.status == 404:
        raise OwnershipError(WELL_KNOWN_NOT_FOUND, "well-known file not found")
    if result.status != 200:
        raise OwnershipError(
            WELL_KNOWN_ERROR, "unexpected HTTP status %d" % result.status
        )
    if len(result.body) > _MAX_BODY:
        raise OwnershipError(WELL_KNOWN_ERROR, "well-known file exceeds 4 KiB")
    if result.body.strip() != ("pry-verify=" + challenge).encode("utf-8"):
        raise OwnershipError(
            WELL_KNOWN_MISMATCH, "well-known content does not match the challenge"
        )
