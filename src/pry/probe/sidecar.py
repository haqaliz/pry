"""Read-only probe sidecar. Standard library only; mounted alone in the sandbox.

This file is copied into a python:3.9-slim container and run as
``python /pry/sidecar.py <probe> <base_url>``. It must never import ``pry.*``:
the result shape and redaction logic are duplicated on purpose so raw secrets
never leave the container.
"""

import http.client
import json
import re
import socket
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass

BODY_LIMIT = 4096
ENDPOINT_LIMIT = 2048
TIMEOUT = 5
ORIGIN = "https://pry.invalid"
USER_AGENT = "pry/0.1"

EXPOSED = "EXPOSED"
NOT_REPRODUCED = "NOT_REPRODUCED"
UNVERIFIED = "UNVERIFIED"
OBSERVED = "OBSERVED"
THROTTLED = "THROTTLED"

TARGET_UNREACHABLE = "TARGET_UNREACHABLE"
REQUEST_TIMEOUT = "REQUEST_TIMEOUT"
REQUEST_FAILED = "REQUEST_FAILED"
INVALID_ENDPOINT = "INVALID_ENDPOINT"
INVALID_COUNT = "INVALID_COUNT"

RATE_LIMIT = "rate_limit"
RATE_LIMIT_MIN = 1
RATE_LIMIT_MAX = 20
RATE_LIMIT_SPACING = 0.1

HEADER_PROBE = "headers"
HSTS_HEADER = "strict-transport-security"
RECOMMENDED_HEADERS = (
    "content-security-policy",
    "x-content-type-options",
    "x-frame-options",
    "referrer-policy",
    "permissions-policy",
    "cross-origin-opener-policy",
)

IDOR_CONTROL_FAILED = "IDOR_CONTROL_FAILED"
REDACTED = "[redacted]"
REDACTED_HEADERS = frozenset(
    (
        "cookie",
        "authorization",
        "set-cookie",
        "x-api-key",
        "proxy-authorization",
    )
)

ERROR_PATH = "/__pry_missing__?id=%27"
SECRET_PATHS = (
    "/.env",
    "/.git/config",
    "/.git/HEAD",
    "/config.json",
    "/.aws/credentials",
    "/backup.sql",
)


@dataclass(frozen=True)
class Response:
    status: int
    headers: dict
    body: str
    final_url: str


class TransportError(Exception):
    """A request that could not produce a response, with a named cause."""

    def __init__(self, cause: str, message: str) -> None:
        super().__init__(message)
        self.cause = cause
        self.message = message


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


_OPENER = urllib.request.build_opener(_NoRedirect)

_ERROR_SIGNATURES = (
    (
        "python traceback",
        re.compile(
            r"(?s)Traceback \(most recent call last\):.*?\n\s+File \"[^\"]+\", line \d+"
        ),
    ),
    (
        "javascript stack",
        re.compile(r"(?m)^\s+at\s+\S.*?:\d+:\d+\)?\s*$"),
    ),
    (
        "sql error",
        re.compile(
            r"(?i)You have an error in your SQL syntax"
            r"|SQLSTATE\[\w+\]"
            r"|Unterminated quoted string"
            r"|PG::SyntaxError"
            r"|ORA-\d{5}"
            r"|near \"[^\"]*\": syntax error"
        ),
    ),
    (
        "framework debug",
        re.compile(
            r"(?i)Werkzeug Debugger"
            r"|Django Version:"
            r"|You're seeing this error because you have DEBUG = True"
            r"|ActiveRecord::StatementInvalid"
        ),
    ),
)

# Key names are the strong signal; the value still has to look like one.
_SECRET = re.compile(
    r"(?i)"
    r"(?P<key>[A-Za-z0-9_.-]*"
    r"(?:SECRET|PASSWORD|PASSWD|PRIVATE_KEY|ACCESS_KEY|API_KEY|AUTH_TOKEN"
    r"|DATABASE_URL|DB_URL|CONNECTION_STRING|DSN|CREDENTIALS)"
    r"[A-Za-z0-9_.-]*)"
    r"(?P<sep>\s*[=:]\s*[\"']?)(?P<value>[^\s\"',}]+)"
)
_PRIVATE_KEY_BLOCK = re.compile(
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?"
    r"(?:-----END [A-Z0-9 ]*PRIVATE KEY-----|$)",
    re.S,
)
_PLACEHOLDERS = frozenset(
    (
        "changeme",
        "change-me",
        "password",
        "secret",
        "example",
        "example-secret",
        "your-secret",
        "your_secret",
        "placeholder",
        "todo",
        "null",
        "none",
        "xxx",
        "xxxx",
    )
)
_URL_USERINFO = re.compile(r"(?i)\b([a-z][a-z0-9+.\-]*://)[^/\s@]+@")


def _headers(headers) -> dict:
    if not headers:
        return {}
    items = headers.items() if hasattr(headers, "items") else headers
    return {str(name).lower(): str(value) for name, value in items}


def _redact_headers(headers) -> dict:
    if not isinstance(headers, dict):
        return {}
    return {
        str(name).lower(): REDACTED
        if str(name).lower() in REDACTED_HEADERS
        else str(value)
        for name, value in headers.items()
    }


def _read_text(response) -> str:
    raw = response.read(BODY_LIMIT)
    if isinstance(raw, bytes):
        return raw.decode("utf-8", "replace")
    return str(raw)


def _status(response) -> int:
    status = getattr(response, "status", None)
    if status is None:
        status = response.getcode()
    return int(status)


def _transport_error(exc: urllib.error.URLError) -> TransportError:
    if isinstance(exc.reason, socket.timeout):
        return TransportError(REQUEST_TIMEOUT, "request timed out")
    return TransportError(TARGET_UNREACHABLE, str(exc.reason))


def urllib_fetch(method: str, url: str, headers: dict, opener=None) -> Response:
    """Make one request; never follow a redirect, cap the body, name failures."""
    open_url = opener.open if opener is not None else _OPENER.open
    try:
        request = urllib.request.Request(url, headers=dict(headers), method=method)
    except ValueError as exc:
        raise TransportError(REQUEST_FAILED, str(exc)) from exc
    try:
        response = open_url(request, timeout=TIMEOUT)
    except urllib.error.HTTPError as exc:
        return Response(
            exc.code, _headers(exc.headers), _read_text(exc), exc.geturl() or url
        )
    except urllib.error.URLError as exc:
        raise _transport_error(exc) from exc
    except socket.timeout as exc:
        raise TransportError(REQUEST_TIMEOUT, "request timed out") from exc
    except (OSError, http.client.HTTPException, ValueError) as exc:
        raise TransportError(TARGET_UNREACHABLE, str(exc)) from exc
    try:
        return Response(
            _status(response),
            _headers(response.headers),
            _read_text(response),
            response.geturl() or url,
        )
    except (OSError, http.client.HTTPException) as exc:
        raise TransportError(
            TARGET_UNREACHABLE, "cannot read response: %s" % exc
        ) from exc
    finally:
        close = getattr(response, "close", None)
        if close is not None:
            close()


def _request(method: str, url: str, headers: dict) -> dict:
    return {"method": method, "url": url, "headers": _headers(headers)}


def _result(probe, verdict, cause, evidence, method, url, headers, response):
    return {
        "probe": probe,
        "verdict": verdict,
        "cause": cause,
        "evidence": evidence,
        "request": _request(method, url, headers),
        "response": None
        if response is None
        else {
            "status": response.status,
            "headers": _headers(response.headers),
            "body": (response.body or "")[:BODY_LIMIT],
        },
    }


def _transport_result(probe, method, url, headers, exc):
    return _result(
        probe,
        UNVERIFIED,
        exc.cause,
        "transport failure: %s" % (exc.message or "request failed"),
        method,
        url,
        headers,
        None,
    )


def _origin(url: str):
    parts = urllib.parse.urlsplit(url or "")
    return (parts.scheme.lower(), parts.netloc.lower())


def _same_origin(base_url: str, url: str) -> bool:
    return _origin(base_url) == _origin(url)


def _redact_urls(text: str) -> str:
    return _URL_USERINFO.sub(r"\1[redacted]@", text)


def _redact_all_secrets(text: str) -> str:
    def replace(match):
        return match.group("key") + match.group("sep") + "[redacted]"

    text = _SECRET.sub(replace, text)
    text = _PRIVATE_KEY_BLOCK.sub("[redacted private key]", text)
    return _redact_urls(text)


def _is_secret_value(value: str) -> bool:
    value = value.strip("\"'")
    return len(value) >= 6 and value.lower() not in _PLACEHOLDERS


def _match_error(body: str):
    for name, pattern in _ERROR_SIGNATURES:
        match = pattern.search(body or "")
        if match is not None:
            snippet = " ".join(match.group(0).split())
            return name, snippet[:160]
    return None


def probe_cors(base_url: str, fetch=None) -> dict:
    fetch = fetch if fetch is not None else urllib_fetch
    url = base_url.rstrip("/") + "/"
    headers = {"Origin": ORIGIN, "User-Agent": USER_AGENT}
    try:
        response = fetch("GET", url, headers)
    except TransportError as exc:
        return _transport_result("cors", "GET", url, headers, exc)

    values = _headers(response.headers)
    allowed = values.get("access-control-allow-origin")
    credentials = (
        values.get("access-control-allow-credentials", "").strip().lower() == "true"
    )
    if allowed == ORIGIN and credentials:
        verdict = EXPOSED
        evidence = (
            "Access-Control-Allow-Origin reflects %s with "
            "Access-Control-Allow-Credentials: true" % ORIGIN
        )
    elif allowed == "*":
        verdict = NOT_REPRODUCED
        evidence = "'*' cannot carry credentials; browsers reject the pair"
    elif allowed == ORIGIN:
        verdict = NOT_REPRODUCED
        evidence = "origin reflected without Access-Control-Allow-Credentials: true"
    elif allowed is not None:
        verdict = NOT_REPRODUCED
        evidence = "origin not reflected in Access-Control-Allow-Origin"
    else:
        verdict = NOT_REPRODUCED
        evidence = "no Access-Control-Allow-Origin header"
    return _result(
        "cors", verdict, None, evidence, "GET", url, headers, response
    )


def probe_errors(base_url: str, fetch=None) -> dict:
    fetch = fetch if fetch is not None else urllib_fetch
    url = base_url.rstrip("/") + ERROR_PATH
    headers = {"User-Agent": USER_AGENT}
    try:
        response = fetch("GET", url, headers)
    except TransportError as exc:
        return _transport_result("errors", "GET", url, headers, exc)

    if not 400 <= response.status <= 599:
        return _result(
            "errors",
            NOT_REPRODUCED,
            None,
            "response status %d is not an error page" % response.status,
            "GET",
            url,
            headers,
            response,
        )
    matched = _match_error(response.body)
    if matched is None:
        return _result(
            "errors",
            NOT_REPRODUCED,
            None,
            "no strong error signature in the %d response" % response.status,
            "GET",
            url,
            headers,
            response,
        )
    name, snippet = matched
    return _result(
        "errors",
        EXPOSED,
        None,
        "%s signature in a %d response: %s" % (name, response.status, snippet),
        "GET",
        url,
        headers,
        response,
    )


def probe_secrets(base_url: str, fetch=None) -> dict:
    fetch = fetch if fetch is not None else urllib_fetch
    headers = {"User-Agent": USER_AGENT}
    first_url = None
    first_response = None
    for path in SECRET_PATHS:
        url = base_url.rstrip("/") + path
        try:
            response = fetch("GET", url, headers)
        except TransportError as exc:
            return _transport_result("secrets", "GET", url, headers, exc)

        match = _SECRET.search(response.body or "")
        if match is not None:
            # Redact before choosing a verdict: a rejected response must not
            # leak a value either.
            response = Response(
                response.status,
                response.headers,
                _redact_all_secrets(response.body),
                response.final_url,
            )
        if first_response is None:
            first_url, first_response = url, response

        if not 200 <= response.status < 300:
            continue
        if not _same_origin(base_url, response.final_url):
            continue
        if match is None or not _is_secret_value(match.group("value")):
            continue
        return _result(
            "secrets",
            EXPOSED,
            None,
            "%s with a value found in %s" % (match.group("key"), path),
            "GET",
            url,
            headers,
            response,
        )

    return _result(
        "secrets",
        NOT_REPRODUCED,
        None,
        "checked %d secret paths; no secret signature found in a "
        "same-origin 200 response" % len(SECRET_PATHS),
        "GET",
        first_url,
        headers,
        first_response,
    )


def _is_endpoint_path(path) -> bool:
    if not isinstance(path, str) or not path or len(path) > ENDPOINT_LIMIT:
        return False
    if not path.startswith("/") or path.startswith("//") or "://" in path:
        return False
    return not any(
        char.isspace() or ord(char) < 32 or ord(char) == 127 for char in path
    )


def probe_unauth(base_url: str, path: str, fetch=None) -> dict:
    """GET a declared-protected path with no credentials and decide exposure."""
    fetch = fetch if fetch is not None else urllib_fetch
    headers = {"User-Agent": USER_AGENT}
    if not _is_endpoint_path(path):
        return _result(
            "unauth",
            UNVERIFIED,
            INVALID_ENDPOINT,
            "invalid endpoint path %r: not path-only" % (path,),
            "GET",
            path,
            headers,
            None,
        )

    url = base_url.rstrip("/") + path
    try:
        response = fetch("GET", url, headers)
    except TransportError as exc:
        return _transport_result("unauth", "GET", url, headers, exc)

    content_type = _headers(response.headers).get("content-type", "")
    body = response.body or ""
    if response.status in (401, 403, 404):
        return _result(
            "unauth",
            NOT_REPRODUCED,
            None,
            "declared-protected path %s returned status %d (content type %r); "
            "the request was rejected"
            % (path, response.status, content_type),
            "GET",
            url,
            headers,
            response,
        )
    if not 200 <= response.status < 300:
        return _result(
            "unauth",
            UNVERIFIED,
            None,
            "declared-protected path %s returned status %d (content type %r); "
            "cannot confirm the check" % (path, response.status, content_type),
            "GET",
            url,
            headers,
            response,
        )
    if not body.strip():
        return _result(
            "unauth",
            NOT_REPRODUCED,
            None,
            "declared-protected path %s returned status %d (content type %r) "
            "with an empty body" % (path, response.status, content_type),
            "GET",
            url,
            headers,
            response,
        )
    if "json" in content_type.lower() or body.lstrip().startswith(("{", "[")):
        return _result(
            "unauth",
            EXPOSED,
            None,
            "declared-protected path %s returned status %d (content type %r) "
            "with a non-empty JSON body and no credentials"
            % (path, response.status, content_type),
            "GET",
            url,
            headers,
            response,
        )
    if "html" in content_type.lower():
        return _result(
            "unauth",
            NOT_REPRODUCED,
            None,
            "declared-protected path %s returned status %d (content type %r); "
            "likely a login page" % (path, response.status, content_type),
            "GET",
            url,
            headers,
            response,
        )
    return _result(
        "unauth",
        NOT_REPRODUCED,
        None,
        "declared-protected path %s returned status %d (content type %r) "
        "with no JSON body" % (path, response.status, content_type),
        "GET",
        url,
        headers,
        response,
    )


def _idor_result(verdict, cause, evidence, url, headers, response):
    return {
        "probe": "idor",
        "verdict": verdict,
        "cause": cause,
        "evidence": evidence,
        "request": _request("GET", url, _redact_headers(headers)),
        "response": None
        if response is None
        else {
            "status": response.status,
            "headers": _redact_headers(response.headers),
            "body": (response.body or "")[:BODY_LIMIT],
        },
    }


def _idor_json_ok(response):
    body = response.body or ""
    content_type = _headers(response.headers).get("content-type", "")
    return (
        200 <= response.status < 300
        and bool(body.strip())
        and (
            "json" in content_type.lower()
            or body.lstrip().startswith(("{", "["))
        )
    )


def _idor_attempt(fetch, url, headers):
    try:
        return fetch("GET", url, dict(headers)), None
    except TransportError as exc:
        return None, exc


def _idor_control_evidence(label, path, response, error):
    if error is not None:
        return "control %s: GET %s failed: %s" % (
            label,
            path,
            error.message or "request failed",
        )
    if _idor_json_ok(response):
        return "control %s: GET %s returned status %d with a non-empty JSON body" % (
            label,
            path,
            response.status,
        )
    return (
        "control %s: GET %s returned status %d (not a 2xx JSON response)"
        % (label, path, response.status)
    )


def probe_idor(
    base_url, headers_a, headers_b, object_a, object_b, fetch=None
) -> dict:
    """Run A->A and B->B controls, then A->B; only a clean cross is EXPOSED."""
    fetch = fetch if fetch is not None else urllib_fetch
    for path in (object_a, object_b):
        if not _is_endpoint_path(path):
            return _idor_result(
                UNVERIFIED,
                INVALID_ENDPOINT,
                "invalid object path %r: not path-only" % (path,),
                path,
                headers_a,
                None,
            )

    base = base_url.rstrip("/")
    attempts = []
    for label, path, identity_headers in (
        ("A", object_a, headers_a),
        ("B", object_b, headers_b),
    ):
        response, error = _idor_attempt(fetch, base + path, identity_headers)
        attempts.append((label, path, identity_headers, response, error))

    evidence = "; ".join(
        _idor_control_evidence(label, path, response, error)
        for label, path, _identity_headers, response, error in attempts
    )
    failing = next(
        (
            attempt
            for attempt in attempts
            if attempt[3] is None or not _idor_json_ok(attempt[3])
        ),
        None,
    )
    if failing is not None:
        _label, path, identity_headers, response, _error = failing
        return _idor_result(
            UNVERIFIED,
            IDOR_CONTROL_FAILED,
            evidence + "; the cross request was not attempted",
            base + path,
            identity_headers,
            response,
        )

    cross_url = base + object_b
    response, error = _idor_attempt(fetch, cross_url, headers_a)
    if error is not None:
        return _idor_result(
            UNVERIFIED,
            error.cause,
            evidence
            + "; cross: GET %s failed: %s"
            % (object_b, error.message or "request failed"),
            cross_url,
            headers_a,
            None,
        )

    if _idor_json_ok(response):
        verdict = EXPOSED
        cause = None
        cross = (
            "cross: GET %s returned status %d with a non-empty JSON body for "
            "the object declared as identity B's" % (object_b, response.status)
        )
    elif response.status in (401, 403, 404):
        verdict = NOT_REPRODUCED
        cause = None
        cross = "cross: GET %s returned status %d; the request was rejected" % (
            object_b,
            response.status,
        )
    else:
        verdict = UNVERIFIED
        cause = None
        cross = (
            "cross: GET %s returned status %d; cannot confirm the check"
            % (object_b, response.status)
        )
    return _idor_result(
        verdict,
        cause,
        evidence + "; " + cross,
        cross_url,
        headers_a,
        response,
    )


PROBES = {
    "cors": probe_cors,
    "errors": probe_errors,
    "secrets": probe_secrets,
    "unauth": probe_unauth,
}


def _rate_limit_observation(status, evidence, url, headers, response, count, statuses):
    return {
        "probe": RATE_LIMIT,
        "status": status,
        "evidence": evidence,
        "request": _request("GET", url, headers),
        "response": None
        if response is None
        else {
            "status": response.status,
            "headers": _headers(response.headers),
            "body": (response.body or "")[:BODY_LIMIT],
        },
        "count": count,
        "statuses": list(statuses),
    }


def probe_rate_limit(base_url, path, count, fetch=None, sleep=None) -> dict:
    """Send up to ``count`` unauth GETs and observe throttling, never a verdict."""
    fetch = fetch if fetch is not None else urllib_fetch
    sleep = sleep if sleep is not None else time.sleep
    headers = {"User-Agent": USER_AGENT}
    if not _is_endpoint_path(path):
        return _rate_limit_observation(
            UNVERIFIED,
            "%s: invalid endpoint path %r: not path-only"
            % (INVALID_ENDPOINT, path),
            path,
            headers,
            None,
            0,
            [],
        )
    if (
        isinstance(count, bool)
        or not isinstance(count, int)
        or not RATE_LIMIT_MIN <= count <= RATE_LIMIT_MAX
    ):
        return _rate_limit_observation(
            UNVERIFIED,
            "%s: rate-limit count %r is not an integer %d..%d"
            % (INVALID_COUNT, count, RATE_LIMIT_MIN, RATE_LIMIT_MAX),
            base_url.rstrip("/") + path,
            headers,
            None,
            0,
            [],
        )

    url = base_url.rstrip("/") + path
    statuses = []
    response = None
    for index in range(count):
        attempt = index + 1
        if index:
            sleep(RATE_LIMIT_SPACING)
        try:
            response = fetch("GET", url, headers)
        except TransportError as exc:
            return _rate_limit_observation(
                UNVERIFIED,
                "transport failure at request %d/%d: %s"
                % (attempt, count, exc.message or "request failed"),
                url,
                headers,
                None,
                attempt,
                statuses,
            )
        statuses.append(response.status)
        retry_after = _headers(response.headers).get("retry-after")
        if response.status in (429, 503) or retry_after is not None:
            evidence = "throttled at request %d/%d: status %d" % (
                attempt,
                count,
                response.status,
            )
            if retry_after is not None:
                evidence += " with Retry-After: %s" % retry_after
            return _rate_limit_observation(
                THROTTLED, evidence, url, headers, response, attempt, statuses
            )
        if not 200 <= response.status < 300:
            return _rate_limit_observation(
                UNVERIFIED,
                "control request %d/%d returned status %d; the endpoint is "
                "not usable for a rate-limit observation"
                % (attempt, count, response.status),
                url,
                headers,
                response,
                attempt,
                statuses,
            )
    return _rate_limit_observation(
        OBSERVED,
        "%d requests accepted without throttling (hardening observation)"
        % count,
        url,
        headers,
        response,
        count,
        statuses,
    )


def _headers_observation(status, evidence, url, headers, response, missing, present):
    return {
        "probe": HEADER_PROBE,
        "status": status,
        "evidence": evidence,
        "request": _request("GET", url, headers),
        "response": None
        if response is None
        else {
            "status": response.status,
            "headers": _headers(response.headers),
            "body": (response.body or "")[:BODY_LIMIT],
        },
        "missing": list(missing),
        "present": list(present),
    }


def probe_headers(base_url: str, fetch=None) -> dict:
    """Observe recommended response headers on '/', never a verdict."""
    fetch = fetch if fetch is not None else urllib_fetch
    url = base_url.rstrip("/") + "/"
    headers = {"User-Agent": USER_AGENT}
    recommended = list(RECOMMENDED_HEADERS)
    if urllib.parse.urlsplit(url).scheme.lower() == "https":
        recommended.append(HSTS_HEADER)
    try:
        response = fetch("GET", url, headers)
    except TransportError as exc:
        return _headers_observation(
            UNVERIFIED,
            "%s: transport failure: %s"
            % (exc.cause, exc.message or "request failed"),
            url,
            headers,
            None,
            [],
            [],
        )

    values = _headers(response.headers)
    missing = [name for name in recommended if name not in values]
    present = [name for name in recommended if name in values]
    return _headers_observation(
        OBSERVED,
        "%d recommended response headers checked on /: %d present, %d "
        "missing (hardening observation)"
        % (len(recommended), len(present), len(missing)),
        url,
        headers,
        response,
        missing,
        present,
    )


def _identity_headers(data, field):
    identity = data.get(field)
    headers = identity.get("headers") if isinstance(identity, dict) else None
    if not isinstance(headers, dict) or not all(
        isinstance(name, str) and isinstance(value, str)
        for name, value in headers.items()
    ):
        raise ValueError("invalid idor config: %s.headers" % field)
    return headers


def _read_idor_config(path):
    try:
        with open(path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, ValueError):
        raise ValueError("cannot read the idor config")
    if not isinstance(data, dict):
        raise ValueError("invalid idor config: expected a JSON object")
    for field in ("object_a", "object_b"):
        if not isinstance(data.get(field), str):
            raise ValueError("invalid idor config: %s" % field)
    return (
        _identity_headers(data, "identity_a"),
        _identity_headers(data, "identity_b"),
        data.get("object_a"),
        data.get("object_b"),
    )


def main(argv=None, fetch=None, sleep=None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    usage = (
        "usage: sidecar.py {cors|errors|secrets|headers} BASE_URL | "
        "sidecar.py unauth BASE_URL PATH | "
        "sidecar.py rate_limit BASE_URL PATH COUNT | "
        "sidecar.py idor BASE_URL CONFIG_PATH\n"
    )
    if not args:
        sys.stderr.write(usage)
        return 2
    if args[0] == HEADER_PROBE:
        if len(args) != 2:
            sys.stderr.write(usage)
            return 2
        print(
            json.dumps(
                probe_headers(args[1], fetch=fetch), sort_keys=True
            )
        )
        return 0
    if args[0] == "idor":
        if len(args) != 3:
            sys.stderr.write(usage)
            return 2
        _, base_url, config_path = args
        try:
            headers_a, headers_b, object_a, object_b = _read_idor_config(
                config_path
            )
        except ValueError as exc:
            sys.stderr.write("error: %s\n" % exc)
            sys.stderr.write(usage)
            return 2
        print(
            json.dumps(
                probe_idor(
                    base_url,
                    headers_a,
                    headers_b,
                    object_a,
                    object_b,
                    fetch=fetch,
                ),
                sort_keys=True,
            )
        )
        return 0
    if args[0] == "rate_limit":
        if len(args) != 4:
            sys.stderr.write(usage)
            return 2
        _, base_url, path, raw_count = args
        try:
            count = int(raw_count)
        except ValueError:
            sys.stderr.write(usage)
            return 2
        print(
            json.dumps(
                probe_rate_limit(
                    base_url, path, count, fetch=fetch, sleep=sleep
                ),
                sort_keys=True,
            )
        )
        return 0
    if args[0] == "unauth":
        if len(args) != 3:
            sys.stderr.write(usage)
            return 2
        _, base_url, path = args
        print(
            json.dumps(
                probe_unauth(base_url, path, fetch=fetch), sort_keys=True
            )
        )
        return 0
    if len(args) != 2 or args[0] not in PROBES:
        sys.stderr.write(usage)
        return 2
    probe, base_url = args
    print(json.dumps(PROBES[probe](base_url, fetch=fetch), sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
