"""Local SSRF Level 1: the declared fetch, its payload, and the stored result.

The callback hit is the proof; the app response is evidence. A hit proves the
app fetched a URL on the sandbox network, not arbitrary external egress.
"""

import re
import secrets
from dataclasses import dataclass

from pry.probe.results import (
    BODY_LIMIT,
    EXPOSED,
    NOT_REPRODUCED,
    UNVERIFIED,
    ProbeError,
    ProbeResult,
)

SSRF_CONFIG_INVALID = "SSRF_CONFIG_INVALID"
SSRF_APP_REQUEST_FAILED = "SSRF_APP_REQUEST_FAILED"
SSRF_HIT_READ_FAILED = "SSRF_HIT_READ_FAILED"
SSRF_PROBE_INVALID = "SSRF_PROBE_INVALID"
SSRF_PROBE_FAILED = "SSRF_PROBE_FAILED"

REDACTED = "[redacted]"
REDACTED_HEADERS = frozenset(
    (
        "cookie",
        "authorization",
        "set-cookie",
        "x-api-key",
        "api-key",
        "proxy-authorization",
    )
)
_PARAMETER = re.compile(r"^[A-Za-z_][A-Za-z0-9_.-]{0,63}\Z")


@dataclass(frozen=True)
class SsrfConfig:
    endpoint: str
    parameter: str


def validate_ssrf(endpoint, parameter) -> SsrfConfig:
    """Accept a path-only endpoint and a token-like query parameter."""
    from pry.probe.scan import validate_endpoints

    try:
        validate_endpoints([endpoint])
    except ProbeError as exc:
        raise ProbeError(
            SSRF_CONFIG_INVALID, "invalid ssrf endpoint: %s" % exc.message
        ) from exc
    if not isinstance(parameter, str) or not _PARAMETER.match(parameter):
        raise ProbeError(
            SSRF_CONFIG_INVALID,
            "invalid ssrf parameter %r: expected a name starting with a letter "
            "or underscore, then letters, digits, '_', '.', or '-' (at most 64)"
            % (parameter,),
        )
    return SsrfConfig(endpoint=endpoint, parameter=parameter)


def new_nonce() -> str:
    return secrets.token_hex(16)


def redact_headers(headers) -> dict:
    if not isinstance(headers, dict):
        return {}
    return {
        str(name).lower(): REDACTED
        if str(name).lower() in REDACTED_HEADERS
        else str(value)
        for name, value in headers.items()
    }


def _valid_request(raw) -> bool:
    return (
        isinstance(raw, dict)
        and isinstance(raw.get("method"), str)
        and isinstance(raw.get("url"), str)
    )


def _app_request(payload, config) -> dict:
    raw = payload.get("request") if isinstance(payload, dict) else None
    if _valid_request(raw):
        return {
            "method": raw["method"],
            "url": raw["url"],
            "headers": redact_headers(raw.get("headers")),
        }
    return {"method": "GET", "url": config.endpoint, "headers": {}}


def _app_response(raw):
    if not isinstance(raw, dict):
        return None
    status = raw.get("status")
    if not isinstance(status, int) or isinstance(status, bool):
        return None
    if not isinstance(raw.get("headers", {}), dict):
        return None
    return {
        "status": status,
        "headers": redact_headers(raw.get("headers")),
        "body": str(raw.get("body") or "")[:BODY_LIMIT],
    }


def _callback_hit(raw):
    if not isinstance(raw, dict):
        return None
    if not isinstance(raw.get("method"), str):
        return None
    path = raw.get("path")
    if not isinstance(path, str) or not path.startswith("/"):
        return None
    if not isinstance(raw.get("headers", {}), dict):
        return None
    return {
        "status": 200,
        "method": raw["method"],
        "path": path,
        "headers": redact_headers(raw.get("headers")),
    }


def _invalid(request: dict) -> ProbeResult:
    return ProbeResult(
        probe="ssrf",
        verdict=UNVERIFIED,
        cause=SSRF_PROBE_INVALID,
        evidence=(
            "the ssrf probe returned an invalid payload; no verdict is possible"
        ),
        request=request,
        response=None,
    )


def parse_ssrf_result(payload, config: SsrfConfig) -> ProbeResult:
    """Map the probe JSON to a result without trusting or re-raising it."""
    request = _app_request(payload, config)
    if not isinstance(payload, dict):
        return _invalid(request)
    if not _valid_request(payload.get("request")):
        return _invalid(request)

    hit = payload.get("hit")
    if not isinstance(hit, bool):
        return _invalid(request)
    cause = payload.get("cause")
    app_response = _app_response(payload.get("app_response"))

    if hit:
        if cause is not None:
            return _invalid(request)
        callback_hit = _callback_hit(payload.get("callback_hit"))
        if callback_hit is None:
            return _invalid(request)
        if app_response is None:
            evidence = (
                "the callback recorded GET %s for the app request"
                % callback_hit["path"]
            )
        else:
            evidence = (
                "the app responded with status %d and fetched the callback URL: "
                "the callback recorded GET %s"
                % (app_response["status"], callback_hit["path"])
            )
        return ProbeResult(
            probe="ssrf",
            verdict=EXPOSED,
            cause=None,
            evidence=evidence,
            request=request,
            response=callback_hit,
        )

    if cause is None:
        if app_response is None:
            return _invalid(request)
        return ProbeResult(
            probe="ssrf",
            verdict=NOT_REPRODUCED,
            cause=None,
            evidence=(
                "the app responded with status %d but the callback recorded no "
                "request for the nonce" % app_response["status"]
            ),
            request=request,
            response=app_response,
        )

    if cause == SSRF_APP_REQUEST_FAILED:
        return ProbeResult(
            probe="ssrf",
            verdict=UNVERIFIED,
            cause=cause,
            evidence=(
                "ssrf probe failed: the app request did not complete; no "
                "callback request can prove the fetch"
            ),
            request=request,
            response=app_response,
        )
    if cause == SSRF_HIT_READ_FAILED:
        return ProbeResult(
            probe="ssrf",
            verdict=UNVERIFIED,
            cause=cause,
            evidence=(
                "ssrf probe failed: the callback hit log could not be read"
            ),
            request=request,
            response=app_response,
        )
    return _invalid(request)


def ssrf_failure(cause, evidence, app_base, config: SsrfConfig) -> ProbeResult:
    """A host-side SSRF failure that never got a probe payload."""
    return ProbeResult(
        probe="ssrf",
        verdict=UNVERIFIED,
        cause=cause,
        evidence=evidence,
        request={
            "method": "GET",
            "url": app_base.rstrip("/") + config.endpoint,
            "headers": {},
        },
        response=None,
    )
