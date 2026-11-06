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
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass

BODY_LIMIT = 4096
TIMEOUT = 5
ORIGIN = "https://pry.invalid"
USER_AGENT = "pry/0.1"

EXPOSED = "EXPOSED"
NOT_REPRODUCED = "NOT_REPRODUCED"
UNVERIFIED = "UNVERIFIED"

TARGET_UNREACHABLE = "TARGET_UNREACHABLE"
REQUEST_TIMEOUT = "REQUEST_TIMEOUT"
REQUEST_FAILED = "REQUEST_FAILED"

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
    r"\s*[=:]\s*[\"']?(?P<value>[^\s\"',}]+)"
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


def _redact_secret(text: str, key: str) -> str:
    pattern = re.compile(
        r"(?im)^([^\n]*?\b%s\b[^\n]*?[=:][ \t]*)([^\n]*)$" % re.escape(key)
    )
    return pattern.sub(lambda match: match.group(1) + "[redacted]", text)


def _redact_urls(text: str) -> str:
    return _URL_USERINFO.sub(r"\1[redacted]@", text)


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
                _redact_urls(_redact_secret(response.body, match.group("key"))),
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


PROBES = {
    "cors": probe_cors,
    "errors": probe_errors,
    "secrets": probe_secrets,
}


def main(argv=None, fetch=None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if len(args) != 2 or args[0] not in PROBES:
        sys.stderr.write("usage: sidecar.py {cors|errors|secrets} BASE_URL\n")
        return 2
    probe, base_url = args
    print(json.dumps(PROBES[probe](base_url, fetch=fetch), sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
