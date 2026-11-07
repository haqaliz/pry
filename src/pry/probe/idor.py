"""Configured live IDOR check: two identities, two objects, three GETs.

The config holds credentials. It is read once, never stored, and the stored
request/response headers are redacted; only the requests carry the real ones.
"""

import json
import re
import stat
from dataclasses import dataclass
from pathlib import Path

from pry.probe.results import (
    BODY_LIMIT,
    EXPOSED,
    NOT_REPRODUCED,
    UNVERIFIED,
    ProbeError,
    normalize_headers,
)
from pry.probe.scan import validate_endpoints
from pry.probe.sidecar import TransportError, urllib_fetch

IDOR_CONFIG_INVALID = "IDOR_CONFIG_INVALID"
IDOR_CONTROL_FAILED = "IDOR_CONTROL_FAILED"

REDACTED = "[redacted]"
HEADER_VALUE_LIMIT = 4096
REDACTED_HEADERS = frozenset(
    (
        "cookie",
        "authorization",
        "set-cookie",
        "x-api-key",
        "proxy-authorization",
    )
)
FORBIDDEN_HEADERS = frozenset(("host", "content-length", "transfer-encoding"))
_HEADER_NAME = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")


@dataclass(frozen=True)
class IdorConfig:
    headers_a: dict
    headers_b: dict
    object_a: str
    object_b: str


def _invalid(message):
    return ProbeError(IDOR_CONFIG_INVALID, message)


def _read_config(path):
    config_path = Path(path).expanduser()
    try:
        info = config_path.stat()
    except OSError:
        raise _invalid("config file is missing or unreadable")
    if not stat.S_ISREG(info.st_mode):
        raise _invalid("config must be a regular file")
    mode = stat.S_IMODE(info.st_mode)
    if mode & 0o077:
        raise _invalid(
            "config file must not be accessible by group or other (chmod 600)"
        )
    if not mode & 0o400:
        raise _invalid("config file must be readable by its owner")
    try:
        text = config_path.read_text(encoding="utf-8")
    except OSError:
        raise _invalid("config file is unreadable")
    try:
        return json.loads(text)
    except ValueError:
        raise _invalid("config file is not valid JSON")


def _valid_headers(value, field):
    if not isinstance(value, dict) or not value:
        raise _invalid("%s must be a non-empty object of headers" % field)
    headers = {}
    for name, header_value in value.items():
        if not isinstance(name, str) or not _HEADER_NAME.match(name):
            raise _invalid("%s has an invalid header name" % field)
        if name.lower() in FORBIDDEN_HEADERS:
            raise _invalid("%s must not set the %s header" % (field, name))
        if not isinstance(header_value, str) or not header_value:
            raise _invalid(
                "%s header %s must have a non-empty string value"
                % (field, name)
            )
        if len(header_value) > HEADER_VALUE_LIMIT:
            raise _invalid(
                "%s header %s exceeds %d characters"
                % (field, name, HEADER_VALUE_LIMIT)
            )
        if any(ord(char) < 32 or ord(char) == 127 for char in header_value):
            raise _invalid(
                "%s header %s contains a control character" % (field, name)
            )
        headers[name] = header_value
    return headers


def _identity_headers(data, field):
    identity = data.get(field)
    if not isinstance(identity, dict):
        raise _invalid("%s must be an object with headers" % field)
    return _valid_headers(identity.get("headers"), field + ".headers")


def load_idor_config(path):
    """Read and validate a 0600 IDOR config; the path is never reported."""
    data = _read_config(path)
    if not isinstance(data, dict):
        raise _invalid("config must be a JSON object")
    headers_a = _identity_headers(data, "identity_a")
    headers_b = _identity_headers(data, "identity_b")
    object_a = data.get("object_a")
    object_b = data.get("object_b")
    try:
        validate_endpoints([object_a, object_b])
    except ProbeError as exc:
        raise _invalid(
            "object_a and object_b must be path-only: %s" % exc.message
        ) from exc
    return IdorConfig(
        headers_a=headers_a,
        headers_b=headers_b,
        object_a=object_a,
        object_b=object_b,
    )


def _redact_headers(headers):
    return {
        str(name).lower(): REDACTED
        if str(name).lower() in REDACTED_HEADERS
        else str(value)
        for name, value in (headers or {}).items()
    }


def _is_json_ok(response):
    body = response.body or ""
    content_type = normalize_headers(response.headers).get("content-type", "")
    return (
        200 <= response.status < 300
        and bool(body.strip())
        and (
            "json" in content_type.lower()
            or body.lstrip().startswith(("{", "["))
        )
    )


def _attempt(fetch, url, headers):
    try:
        return fetch("GET", url, headers), None
    except TransportError as exc:
        return None, exc


def _result(verdict, cause, evidence, url, headers, response):
    return {
        "probe": "idor",
        "verdict": verdict,
        "cause": cause,
        "evidence": evidence,
        "request": {
            "method": "GET",
            "url": url,
            "headers": _redact_headers(headers),
        },
        "response": None
        if response is None
        else {
            "status": response.status,
            "headers": _redact_headers(response.headers),
            "body": (response.body or "")[:BODY_LIMIT],
        },
    }


def _control_evidence(label, path, response, error):
    if error is not None:
        return "control %s: GET %s failed: %s" % (
            label,
            path,
            error.message or "request failed",
        )
    if _is_json_ok(response):
        return "control %s: GET %s returned status %d with a non-empty JSON body" % (
            label,
            path,
            response.status,
        )
    return (
        "control %s: GET %s returned status %d (not a 2xx JSON response)"
        % (label, path, response.status)
    )


def probe_idor(base_url, config, fetch=None):
    """Run A->A and B->B controls, then A->B; only a clean cross is EXPOSED."""
    fetch = fetch if fetch is not None else urllib_fetch
    base = base_url.rstrip("/")
    attempts = []
    for label, path, headers in (
        ("A", config.object_a, config.headers_a),
        ("B", config.object_b, config.headers_b),
    ):
        response, error = _attempt(fetch, base + path, dict(headers))
        attempts.append((label, path, headers, response, error))

    evidence = "; ".join(
        _control_evidence(label, path, response, error)
        for label, path, _headers, response, error in attempts
    )
    failing = next(
        (
            attempt
            for attempt in attempts
            if attempt[3] is None or not _is_json_ok(attempt[3])
        ),
        None,
    )
    if failing is not None:
        _label, path, headers, response, _error = failing
        return _result(
            UNVERIFIED,
            IDOR_CONTROL_FAILED,
            evidence + "; the cross request was not attempted",
            base + path,
            headers,
            response,
        )

    cross_url = base + config.object_b
    response, error = _attempt(fetch, cross_url, dict(config.headers_a))
    if error is not None:
        return _result(
            UNVERIFIED,
            error.cause,
            evidence
            + "; cross: GET %s failed: %s"
            % (config.object_b, error.message or "request failed"),
            cross_url,
            config.headers_a,
            None,
        )

    if _is_json_ok(response):
        verdict = EXPOSED
        cause = None
        cross = (
            "cross: GET %s returned status %d with a non-empty JSON body for "
            "the object declared as identity B's"
            % (config.object_b, response.status)
        )
    elif response.status in (401, 403, 404):
        verdict = NOT_REPRODUCED
        cause = None
        cross = "cross: GET %s returned status %d; the request was rejected" % (
            config.object_b,
            response.status,
        )
    else:
        verdict = UNVERIFIED
        cause = None
        cross = (
            "cross: GET %s returned status %d; cannot confirm the check"
            % (config.object_b, response.status)
        )
    return _result(
        verdict,
        cause,
        evidence + "; " + cross,
        cross_url,
        config.headers_a,
        response,
    )
