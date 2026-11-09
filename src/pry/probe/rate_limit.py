"""Local rate-limit observation: config, validation, and result parsing.

A rate-limit observation is a hardening observation, not a finding: it has no
verdict, no proof bundle, and is never signed.
"""

from dataclasses import dataclass

from pry.probe.results import BODY_LIMIT, UNVERIFIED, ProbeError

RATE_LIMIT = "rate_limit"
OBSERVED = "OBSERVED"
THROTTLED = "THROTTLED"
RATE_LIMIT_STATUSES = (OBSERVED, THROTTLED, UNVERIFIED)
RATE_LIMIT_CONFIG_INVALID = "RATE_LIMIT_CONFIG_INVALID"
RATE_LIMIT_PROBE_INVALID = "RATE_LIMIT_PROBE_INVALID"
RATE_LIMIT_MIN_COUNT = 1
RATE_LIMIT_MAX_COUNT = 20
RATE_LIMIT_DEFAULT_COUNT = 10


@dataclass(frozen=True)
class RateLimitConfig:
    endpoint: str
    count: int


def validate_rate_limit(endpoint, count) -> RateLimitConfig:
    """Accept a path-only endpoint and a bounded count, or fail before Docker."""
    from pry.probe.scan import validate_endpoints

    try:
        validate_endpoints([endpoint])
    except ProbeError as exc:
        raise ProbeError(
            RATE_LIMIT_CONFIG_INVALID,
            "invalid rate-limit endpoint: %s" % exc.message,
        ) from exc
    if "?" in endpoint or "#" in endpoint:
        raise ProbeError(
            RATE_LIMIT_CONFIG_INVALID,
            "invalid rate-limit endpoint: must not include a query or fragment",
        )
    if (
        isinstance(count, bool)
        or not isinstance(count, int)
        or not RATE_LIMIT_MIN_COUNT <= count <= RATE_LIMIT_MAX_COUNT
    ):
        raise ProbeError(
            RATE_LIMIT_CONFIG_INVALID,
            "invalid rate-limit count %r: expected an integer %d..%d"
            % (count, RATE_LIMIT_MIN_COUNT, RATE_LIMIT_MAX_COUNT),
        )
    return RateLimitConfig(endpoint=endpoint, count=count)


def _request(url) -> dict:
    return {"method": "GET", "url": url if isinstance(url, str) else ""}


def _headers(headers) -> dict:
    if not isinstance(headers, dict):
        return {}
    return {str(name).lower(): str(value) for name, value in headers.items()}


def _valid_response(raw) -> bool:
    return (
        isinstance(raw, dict)
        and isinstance(raw.get("status"), int)
        and not isinstance(raw.get("status"), bool)
        and isinstance(raw.get("headers", {}), dict)
    )


def _invalid(config: RateLimitConfig) -> dict:
    return {
        "probe": RATE_LIMIT,
        "status": UNVERIFIED,
        "evidence": (
            "%s: the rate-limit probe returned an invalid payload; no "
            "observation is possible" % RATE_LIMIT_PROBE_INVALID
        ),
        "request": _request(config.endpoint),
        "response": None,
        "count": 0,
        "statuses": [],
    }


def parse_rate_limit_result(payload, config: RateLimitConfig) -> dict:
    """Normalize the sidecar JSON without trusting it; never build a verdict."""
    if not isinstance(payload, dict):
        return _invalid(config)
    if "verdict" in payload or "proof" in payload:
        return _invalid(config)

    status = payload.get("status")
    evidence = payload.get("evidence")
    count = payload.get("count")
    statuses = payload.get("statuses")
    request = payload.get("request")
    response = payload.get("response")

    if payload.get("probe") != RATE_LIMIT or status not in RATE_LIMIT_STATUSES:
        return _invalid(config)
    if not isinstance(evidence, str) or not evidence:
        return _invalid(config)
    if (
        isinstance(count, bool)
        or not isinstance(count, int)
        or not 0 <= count <= config.count
    ):
        return _invalid(config)
    if not isinstance(statuses, list) or not all(
        isinstance(value, int) and not isinstance(value, bool)
        for value in statuses
    ):
        return _invalid(config)
    if len(statuses) > count:
        return _invalid(config)
    if status in (OBSERVED, THROTTLED) and len(statuses) != count:
        return _invalid(config)
    if (
        not isinstance(request, dict)
        or not isinstance(request.get("method"), str)
        or not isinstance(request.get("url"), str)
        or not isinstance(request.get("headers", {}), dict)
    ):
        return _invalid(config)
    if response is not None and not _valid_response(response):
        return _invalid(config)

    return {
        "probe": RATE_LIMIT,
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
        "count": count,
        "statuses": [int(value) for value in statuses],
    }
