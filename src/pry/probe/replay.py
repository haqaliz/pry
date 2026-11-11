"""Replay a signed read-only proof against its P1-verified live target.

This is a reproducibility check, not a new verdict: it compares the recorded
status with the replay status and never signs a new proof.
"""

import urllib.parse

from pry.own.target import normalize_target
from pry.own.tokens import TokenSigner
from pry.probe.sidecar import TARGET_UNREACHABLE, TransportError, urllib_fetch

MATCH = "MATCH"
MISMATCH = "MISMATCH"
UNVERIFIED = "UNVERIFIED"
REPLAY_INVALID = "REPLAY_INVALID"
REPLAY_LIVE_ONLY = "REPLAY_LIVE_ONLY"
REPLAY_READ_ONLY_ONLY = "REPLAY_READ_ONLY_ONLY"
REPLAY_TARGET_MISMATCH = "REPLAY_TARGET_MISMATCH"
SAFE_HEADERS = ("user-agent", "accept")


class ReplayError(Exception):
    """A replay that cannot run, with a stable cause."""

    def __init__(self, cause, message):
        super().__init__(message)
        self.cause = cause
        self.message = message

    def __str__(self):
        return "%s: %s" % (self.cause, self.message)


def _invalid(message):
    return ReplayError(REPLAY_INVALID, message)


def _origin(url):
    parts = urllib.parse.urlsplit(url or "")
    return (parts.scheme.lower(), parts.netloc.lower())


def _safe_headers(headers):
    if not isinstance(headers, dict):
        return {"user-agent": "pry/0.1"}
    safe = {}
    for name in SAFE_HEADERS:
        value = headers.get(name)
        if isinstance(value, str) and value:
            safe[name] = value
    safe.setdefault("user-agent", "pry/0.1")
    return safe


def replay_bundle(payload, token, fetch=None):
    """Verify shape, prove ownership, one GET, compare statuses only."""
    fetch = fetch if fetch is not None else urllib_fetch
    if not isinstance(payload, dict):
        raise _invalid("replay payload must be an object")

    target = payload.get("target")
    finding = payload.get("finding")
    if not isinstance(target, dict) or not isinstance(finding, dict):
        raise _invalid("replay payload must contain target and finding objects")
    if target.get("kind") != "live":
        raise ReplayError(
            REPLAY_LIVE_ONLY,
            "only live proof bundles can be replayed; local replay is deferred",
        )
    origin_value = target.get("path") or target.get("url")
    try:
        origin = normalize_target(origin_value).origin
    except Exception as exc:
        raise _invalid("bundle target is not a valid URL") from exc

    request = finding.get("request")
    if not isinstance(request, dict):
        raise _invalid("finding request must be an object")
    method = request.get("method")
    if not isinstance(method, str) or method.upper() != "GET":
        raise ReplayError(
            REPLAY_READ_ONLY_ONLY,
            "replay is GET-only; write proofs are not replayed",
        )
    url = request.get("url")
    if not isinstance(url, str) or _origin(url) != _origin(origin):
        raise ReplayError(
            REPLAY_TARGET_MISMATCH,
            "the recorded request URL is not on the bundle target origin",
        )
    parts = urllib.parse.urlsplit(url)
    if parts.username or parts.password:
        raise _invalid("recorded request URL must not contain userinfo")

    response = finding.get("response")
    recorded_status = response.get("status") if isinstance(response, dict) else None
    if (
        isinstance(recorded_status, bool)
        or not isinstance(recorded_status, int)
    ):
        raise _invalid("finding response must contain an integer status")

    # Ownership is proven before the replay request.
    TokenSigner().validate(token, normalize_target(origin))

    safe_headers = _safe_headers(request.get("headers"))
    try:
        replay_response = fetch("GET", url, safe_headers)
    except TransportError as exc:
        return {
            "status": UNVERIFIED,
            "probe": finding.get("probe"),
            "target": origin,
            "recorded_status": recorded_status,
            "cause": exc.cause or TARGET_UNREACHABLE,
            "message": "replay failed: %s" % (exc.message or "request failed"),
        }

    replay_status = replay_response.status
    matched = replay_status == recorded_status
    status = MATCH if matched else MISMATCH
    if matched:
        message = (
            "GET %s returned status %d (recorded %d); status match only, "
            "probe-specific conditions were not re-evaluated"
            % (url, replay_status, recorded_status)
        )
    else:
        message = (
            "GET %s returned status %d (recorded %d); the proof did not "
            "reproduce the same status"
            % (url, replay_status, recorded_status)
        )
    return {
        "status": status,
        "probe": finding.get("probe"),
        "target": origin,
        "recorded_status": recorded_status,
        "replay_status": replay_status,
        "body_bytes": len(replay_response.body or ""),
        "message": message,
    }
