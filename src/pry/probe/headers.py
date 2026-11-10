"""Response header observation: constants and payload validation.

A header observation is hardening evidence, not a finding: it has no verdict,
no proof bundle, and is never signed.
"""

from pry.probe.results import BODY_LIMIT, UNVERIFIED

HEADER_PROBE = "headers"
OBSERVED = "OBSERVED"
HEADER_STATUSES = (OBSERVED, UNVERIFIED)
HEADERS_PROBE_INVALID = "HEADERS_PROBE_INVALID"

RECOMMENDED_HEADERS = (
    "content-security-policy",
    "x-content-type-options",
    "x-frame-options",
    "referrer-policy",
    "permissions-policy",
    "cross-origin-opener-policy",
)
HSTS_HEADER = "strict-transport-security"


def _request(url) -> dict:
    return {"method": "GET", "url": url if isinstance(url, str) else ""}


def _headers(headers) -> dict:
    if not isinstance(headers, dict):
        return {}
    return {str(name).lower(): str(value) for name, value in headers.items()}


def _names(raw):
    if not isinstance(raw, list) or not all(
        isinstance(name, str) for name in raw
    ):
        return None
    return [name.lower() for name in raw]


def _valid_response(raw) -> bool:
    return (
        isinstance(raw, dict)
        and isinstance(raw.get("status"), int)
        and not isinstance(raw.get("status"), bool)
        and isinstance(raw.get("headers", {}), dict)
    )


def _invalid() -> dict:
    return {
        "probe": HEADER_PROBE,
        "status": UNVERIFIED,
        "evidence": (
            "%s: the headers probe returned an invalid payload; no "
            "observation is possible" % HEADERS_PROBE_INVALID
        ),
        "request": _request(""),
        "response": None,
        "missing": [],
        "present": [],
    }


def parse_headers_result(payload) -> dict:
    """Normalize the sidecar JSON without trusting it; never build a verdict."""
    if not isinstance(payload, dict):
        return _invalid()
    if "verdict" in payload or "proof" in payload:
        return _invalid()

    status = payload.get("status")
    evidence = payload.get("evidence")
    request = payload.get("request")
    response = payload.get("response")
    missing = _names(payload.get("missing"))
    present = _names(payload.get("present"))

    if payload.get("probe") != HEADER_PROBE or status not in HEADER_STATUSES:
        return _invalid()
    if not isinstance(evidence, str) or not evidence:
        return _invalid()
    if (
        not isinstance(request, dict)
        or not isinstance(request.get("method"), str)
        or not isinstance(request.get("url"), str)
        or not isinstance(request.get("headers", {}), dict)
    ):
        return _invalid()
    if missing is None or present is None:
        return _invalid()
    if response is not None and not _valid_response(response):
        return _invalid()
    if status == OBSERVED and response is None:
        return _invalid()
    if status == UNVERIFIED and (response is not None or missing or present):
        return _invalid()

    return {
        "probe": HEADER_PROBE,
        "status": status,
        "evidence": evidence,
        "request": {
            "method": request["method"],
            "url": request["url"],
            "headers": _headers(request.get("headers")),
        },
        "response": None
        if response is None
        else {
            "status": response["status"],
            "headers": _headers(response.get("headers")),
            "body": str(response.get("body") or "")[:BODY_LIMIT],
        },
        "missing": missing,
        "present": present,
    }
