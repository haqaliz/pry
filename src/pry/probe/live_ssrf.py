"""Live SSRF Level 1: one declared fetch and a user-owned callback poll.

The callback hit is the only EXPOSED condition. A 2xx app response alone
proves nothing: the app may ignore the URL. The callback is the owner's own
service; Pry sends no auth, cookies, or redirects.
"""

import time
import urllib.parse
from dataclasses import dataclass

from pry.probe.results import (
    BODY_LIMIT,
    EXPOSED,
    NOT_REPRODUCED,
    UNVERIFIED,
    ProbeError,
    ProbeResult,
)
from pry.probe.sidecar import TransportError, urllib_fetch
from pry.probe.ssrf import new_nonce, redact_headers, validate_ssrf

SSRF_CALLBACK_INVALID = "SSRF_CALLBACK_INVALID"
SSRF_CALLBACK_REQUIRED = "SSRF_CALLBACK_REQUIRED"
SSRF_CALLBACK_SAME_ORIGIN = "SSRF_CALLBACK_SAME_ORIGIN"

LIVE_SSRF_CALLBACK_LIMIT = 2048
LIVE_SSRF_POLLS = 3
LIVE_SSRF_POLL_SPACING = 0.5
USER_AGENT = "pry/0.1"
_LOOPBACK_HOSTS = frozenset(("127.0.0.1", "localhost", "::1"))
_DEFAULT_PORTS = {"http": 80, "https": 443}


@dataclass(frozen=True)
class LiveSsrfConfig:
    endpoint: str
    parameter: str
    callback_url: str


def _callback_invalid(message):
    return ProbeError(SSRF_CALLBACK_INVALID, message)


def validate_live_ssrf(endpoint, parameter, callback_url) -> LiveSsrfConfig:
    """Accept a declared fetch and a callback base the owner controls."""
    config = validate_ssrf(endpoint, parameter)
    if callback_url is None:
        raise ProbeError(
            SSRF_CALLBACK_REQUIRED,
            "live ssrf requires --ssrf-callback-url: a base URL you own that "
            "records a GET for a per-run nonce",
        )
    if (
        not isinstance(callback_url, str)
        or not 1 <= len(callback_url) <= LIVE_SSRF_CALLBACK_LIMIT
    ):
        raise _callback_invalid(
            "invalid ssrf callback URL: expected a string of 1..%d characters"
            % LIVE_SSRF_CALLBACK_LIMIT
        )
    if any(
        char.isspace() or ord(char) < 32 or ord(char) == 127
        for char in callback_url
    ):
        raise _callback_invalid(
            "invalid ssrf callback URL: no whitespace or control characters"
        )
    try:
        parts = urllib.parse.urlsplit(callback_url)
        parts.port  # an invalid port raises ValueError
    except ValueError as exc:
        raise _callback_invalid(
            "invalid ssrf callback URL: %s" % exc
        ) from exc
    scheme = parts.scheme.lower()
    if scheme not in _DEFAULT_PORTS:
        raise _callback_invalid(
            "invalid ssrf callback URL: expected an absolute http or https URL"
        )
    if "@" in parts.netloc or parts.username is not None:
        raise _callback_invalid(
            "invalid ssrf callback URL: userinfo is not allowed"
        )
    if parts.query or parts.fragment:
        raise _callback_invalid(
            "invalid ssrf callback URL: no query or fragment; the nonce is "
            "appended as a path segment"
        )
    host = (parts.hostname or "").lower()
    if not host:
        raise _callback_invalid(
            "invalid ssrf callback URL: missing host"
        )
    if scheme == "http" and host not in _LOOPBACK_HOSTS:
        raise _callback_invalid(
            "invalid ssrf callback URL: https is required unless the host is "
            "127.0.0.1, localhost, or [::1]"
        )
    return LiveSsrfConfig(
        endpoint=config.endpoint,
        parameter=config.parameter,
        callback_url=callback_url.rstrip("/"),
    )


def _origin(url):
    parts = urllib.parse.urlsplit(url or "")
    scheme = parts.scheme.lower()
    try:
        port = parts.port
    except ValueError:
        port = None
    if port == _DEFAULT_PORTS.get(scheme):
        port = None
    return (scheme, (parts.hostname or "").lower(), port)


def same_origin(base_url, url) -> bool:
    return _origin(base_url) == _origin(url)


def _pair(response):
    return {
        "status": response.status,
        "headers": redact_headers(response.headers),
        "body": (response.body or "")[:BODY_LIMIT],
    }


def _request(method, url):
    return {
        "method": method,
        "url": url,
        "headers": redact_headers({"User-Agent": USER_AGENT}),
    }


def _result(verdict, cause, evidence, request, response):
    return {
        "probe": "ssrf",
        "verdict": verdict,
        "cause": cause,
        "evidence": evidence,
        "request": request,
        "response": response,
    }


def _with_callback(app, callback):
    response = _pair(app)
    response["callback"] = dict(callback)
    return response


def probe_live_ssrf(base_url, config: LiveSsrfConfig, fetch=None, sleep=None):
    """Send one declared fetch, then poll the owner's callback for the nonce."""
    fetch = fetch if fetch is not None else urllib_fetch
    sleep = sleep if sleep is not None else time.sleep
    nonce = new_nonce()
    callback_url = config.callback_url.rstrip("/") + "/" + nonce
    ssrf_url = (
        base_url.rstrip("/")
        + config.endpoint
        + "?"
        + urllib.parse.urlencode({config.parameter: callback_url})
    )
    headers = {"User-Agent": USER_AGENT}
    request = _request("GET", ssrf_url)

    try:
        app = fetch("GET", ssrf_url, headers)
    except TransportError as exc:
        return _result(
            UNVERIFIED,
            exc.cause,
            "ssrf request failed: %s; no callback request can prove the fetch"
            % (exc.message or "request failed"),
            request,
            None,
        )

    if app.status in (401, 403, 404):
        return _result(
            NOT_REPRODUCED,
            None,
            "the app rejected the declared fetch with status %d; no callback "
            "request can prove a fetch" % app.status,
            request,
            _pair(app),
        )
    if not 200 <= app.status < 300:
        return _result(
            UNVERIFIED,
            None,
            "the app responded with status %d; cannot confirm the fetch"
            % app.status,
            request,
            _pair(app),
        )
    if not same_origin(base_url, app.final_url):
        return _result(
            NOT_REPRODUCED,
            None,
            "the app response came from a different origin; it is not evidence "
            "of a fetch",
            request,
            _pair(app),
        )

    callback = {
        "request": _request("GET", callback_url),
        "response": None,
        "attempts": 0,
    }
    for attempt in range(1, LIVE_SSRF_POLLS + 1):
        sleep(LIVE_SSRF_POLL_SPACING)
        callback["attempts"] = attempt
        try:
            hit = fetch("GET", callback_url, {"User-Agent": USER_AGENT})
        except TransportError as exc:
            return _result(
                UNVERIFIED,
                exc.cause,
                "callback poll %d/%d failed: %s; cannot read the callback hit"
                % (
                    attempt,
                    LIVE_SSRF_POLLS,
                    exc.message or "request failed",
                ),
                request,
                _with_callback(app, callback),
            )
        callback["response"] = _pair(hit)
        if hit.status == 200:
            return _result(
                EXPOSED,
                None,
                "callback recorded GET /%s on poll %d/%d after app returned "
                "status %d" % (nonce, attempt, LIVE_SSRF_POLLS, app.status),
                request,
                _with_callback(app, callback),
            )
        if hit.status == 404:
            continue
        return _result(
            UNVERIFIED,
            None,
            "callback poll %d/%d returned status %d (callback service error); "
            "cannot confirm a hit" % (attempt, LIVE_SSRF_POLLS, hit.status),
            request,
            _with_callback(app, callback),
        )
    return _result(
        NOT_REPRODUCED,
        None,
        "app responded status %d but callback recorded no hit after %d polls"
        % (app.status, LIVE_SSRF_POLLS),
        request,
        _with_callback(app, callback),
    )
