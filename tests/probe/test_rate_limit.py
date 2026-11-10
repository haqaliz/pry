"""Local rate-limit observation tests (AT1-AT3).

Every probe takes an injected ``fetch`` and ``sleep``; nothing here opens a
socket or waits.
"""

import pytest

import pry.probe.sidecar as sidecar
from pry.probe.rate_limit import (
    OBSERVED,
    RATE_LIMIT,
    RATE_LIMIT_CONFIG_INVALID,
    RATE_LIMIT_PROBE_INVALID,
    THROTTLED,
    RateLimitConfig,
    parse_rate_limit_result,
    validate_rate_limit,
)
from pry.probe.results import UNVERIFIED, ProbeError, ProbeResult

BASE = "http://app:3000"
PATH = "/api/ping"
OBSERVATION_KEYS = {
    "probe",
    "status",
    "evidence",
    "request",
    "response",
    "count",
    "statuses",
}


def _response(status=200, headers=None, body="", path=PATH):
    return sidecar.Response(status, headers or {}, body, BASE + path)


class FakeFetch:
    def __init__(self, *responses):
        self.responses = list(responses)
        self.calls = []

    def __call__(self, method, url, headers):
        self.calls.append((method, url, dict(headers)))
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response


class Sleeps:
    def __init__(self):
        self.calls = []

    def __call__(self, seconds):
        self.calls.append(seconds)


def _run(count=10, *responses):
    fetch = FakeFetch(*responses)
    sleeps = Sleeps()
    result = sidecar.probe_rate_limit(
        BASE, PATH, count, fetch=fetch, sleep=sleeps
    )
    return result, fetch, sleeps


def test_all_2xx_is_observed_with_the_request_count_and_statuses():
    result, fetch, sleeps = _run(3, *[_response(200) for _ in range(3)])

    assert result["probe"] == RATE_LIMIT
    assert result["status"] == OBSERVED
    assert result["count"] == 3
    assert result["statuses"] == [200, 200, 200]
    assert result["evidence"] == (
        "3 requests accepted without throttling (hardening observation)"
    )
    assert len(fetch.calls) == 3
    assert sleeps.calls == [0.1, 0.1]
    assert set(result) == OBSERVATION_KEYS
    assert "verdict" not in result
    assert "proof" not in result


def test_the_observation_records_the_last_request_and_response():
    result, _fetch, _sleeps = _run(2, _response(200), _response(204, {}, ""))

    assert result["request"] == {
        "method": "GET",
        "url": BASE + PATH,
        "headers": {"user-agent": sidecar.USER_AGENT},
    }
    assert result["response"]["status"] == 204
    assert result["response"]["headers"] == {}
    assert result["response"]["body"] == ""


def test_the_probe_sends_no_auth_or_cookies():
    result, fetch, _sleeps = _run(2, _response(200), _response(200))

    assert fetch.calls == [
        ("GET", BASE + PATH, {"User-Agent": sidecar.USER_AGENT}),
        ("GET", BASE + PATH, {"User-Agent": sidecar.USER_AGENT}),
    ]
    assert result["request"]["headers"] == {"user-agent": sidecar.USER_AGENT}


def test_429_stops_at_request_four_and_records_the_throttle():
    result, fetch, sleeps = _run(
        10,
        *([_response(200)] * 3 + [_response(429, {"Retry-After": "30"})]),
    )

    assert result["status"] == THROTTLED
    assert result["count"] == 4
    assert result["statuses"] == [200, 200, 200, 429]
    assert "request 4/10" in result["evidence"]
    assert "429" in result["evidence"]
    assert "Retry-After: 30" in result["evidence"]
    assert len(fetch.calls) == 4
    assert sleeps.calls == [0.1, 0.1, 0.1]


def test_503_is_throttled():
    result, fetch, _sleeps = _run(5, _response(503))

    assert result["status"] == THROTTLED
    assert result["count"] == 1
    assert result["statuses"] == [503]
    assert "request 1/5" in result["evidence"]
    assert "503" in result["evidence"]
    assert len(fetch.calls) == 1


def test_a_retry_after_header_is_throttled_even_on_a_2xx():
    result, _fetch, _sleeps = _run(
        5, _response(200, {"Retry-After": "1"})
    )

    assert result["status"] == THROTTLED
    assert result["statuses"] == [200]
    assert "Retry-After: 1" in result["evidence"]


@pytest.mark.parametrize("status", [401, 403, 404, 500])
def test_a_control_status_is_unverified_and_stops(status):
    result, fetch, _sleeps = _run(10, _response(status))

    assert result["status"] == UNVERIFIED
    assert result["count"] == 1
    assert result["statuses"] == [status]
    assert str(status) in result["evidence"]
    assert len(fetch.calls) == 1
    assert result["response"]["status"] == status


def test_a_non_2xx_non_throttle_status_is_unverified():
    result, _fetch, _sleeps = _run(3, _response(302, {"Location": "/login"}))

    assert result["status"] == UNVERIFIED
    assert result["statuses"] == [302]
    assert "302" in result["evidence"]


def test_a_transport_failure_is_unverified_with_a_named_evidence():
    result, fetch, _sleeps = _run(
        10,
        _response(200),
        sidecar.TransportError(sidecar.REQUEST_TIMEOUT, "timed out"),
    )

    assert result["status"] == UNVERIFIED
    assert result["response"] is None
    assert result["count"] == 2
    assert result["statuses"] == [200]
    assert "transport failure" in result["evidence"]
    assert "request 2/10" in result["evidence"]
    assert "timed out" in result["evidence"]
    assert "Traceback" not in result["evidence"]
    assert len(fetch.calls) == 2


def test_count_one_makes_one_request_and_does_not_sleep():
    result, fetch, sleeps = _run(1, _response(200))

    assert result["status"] == OBSERVED
    assert result["count"] == 1
    assert result["statuses"] == [200]
    assert len(fetch.calls) == 1
    assert sleeps.calls == []


def test_count_twenty_is_the_upper_bound():
    result, fetch, sleeps = _run(20, *[_response(200) for _ in range(20)])

    assert result["status"] == OBSERVED
    assert result["count"] == 20
    assert len(result["statuses"]) == 20
    assert len(fetch.calls) == 20
    assert sleeps.calls == [0.1] * 19


@pytest.mark.parametrize("count", [0, 21, -1, "10", True, None])
def test_an_out_of_bounds_count_is_unverified_before_any_request(count):
    result, fetch, _sleeps = _run(count, _response(200))

    assert result["status"] == UNVERIFIED
    assert result["count"] == 0
    assert result["statuses"] == []
    assert result["response"] is None
    assert "count" in result["evidence"]
    assert fetch.calls == []


@pytest.mark.parametrize(
    "path", ["http://evil.invalid", "api/ping", "/api ping", ""]
)
def test_an_invalid_path_is_unverified_before_any_request(path):
    fetch = FakeFetch()

    result = sidecar.probe_rate_limit(BASE, path, 10, fetch=fetch)

    assert result["status"] == UNVERIFIED
    assert result["count"] == 0
    assert result["statuses"] == []
    assert result["response"] is None
    assert "path" in result["evidence"]
    assert fetch.calls == []


def test_the_observation_caps_the_captured_body_at_4_kib():
    body = "x" * (sidecar.BODY_LIMIT * 3)

    result, _fetch, _sleeps = _run(1, _response(200, {}, body))

    assert len(result["response"]["body"]) == sidecar.BODY_LIMIT
    assert sidecar.BODY_LIMIT == 4096


def test_the_sidecar_observation_is_not_a_probe_result():
    result, _fetch, _sleeps = _run(1, _response(200))

    assert isinstance(result, dict)
    with pytest.raises(TypeError):
        ProbeResult(**result)


def _observation(status=OBSERVED, **overrides):
    observation = {
        "probe": RATE_LIMIT,
        "status": status,
        "evidence": "3 requests accepted without throttling "
        "(hardening observation)",
        "request": {
            "method": "GET",
            "url": BASE + PATH,
            "headers": {"User-Agent": sidecar.USER_AGENT},
        },
        "response": {"status": 200, "headers": {}, "body": "ok"},
        "count": 3,
        "statuses": [200, 200, 200],
    }
    observation.update(overrides)
    return observation


def test_validate_rate_limit_accepts_a_path_only_endpoint_and_a_count():
    assert validate_rate_limit(PATH, 10) == RateLimitConfig(
        endpoint=PATH, count=10
    )


@pytest.mark.parametrize(
    "endpoint",
    [
        "http://evil.invalid",
        "https://evil.invalid/api",
        "api/ping",
        "",
        "/api ping",
        "/api/ping?x=1",
        "/api/ping#frag",
        "/" + "a" * 2048,
    ],
)
def test_validate_rate_limit_rejects_a_non_path_endpoint(endpoint):
    with pytest.raises(ProbeError) as exc:
        validate_rate_limit(endpoint, 10)

    assert exc.value.cause == RATE_LIMIT_CONFIG_INVALID


@pytest.mark.parametrize("count", [0, 21, -1, "10", True, None])
def test_validate_rate_limit_rejects_an_out_of_bounds_count(count):
    with pytest.raises(ProbeError) as exc:
        validate_rate_limit(PATH, count)

    assert exc.value.cause == RATE_LIMIT_CONFIG_INVALID


@pytest.mark.parametrize("count", [1, 20])
def test_validate_rate_limit_accepts_the_count_bounds(count):
    assert validate_rate_limit(PATH, count).count == count


@pytest.mark.parametrize("status", [OBSERVED, THROTTLED, UNVERIFIED])
def test_parse_rate_limit_result_passes_a_valid_observation_through(status):
    payload = _observation(status)

    result = parse_rate_limit_result(payload, RateLimitConfig(PATH, 10))

    assert isinstance(result, dict)
    assert not isinstance(result, ProbeResult)
    assert set(result) == OBSERVATION_KEYS
    assert result["status"] == status
    assert result["count"] == 3
    assert result["statuses"] == [200, 200, 200]
    assert result["request"]["headers"] == {"user-agent": sidecar.USER_AGENT}


def test_parse_rate_limit_result_caps_the_body_and_lowercases_headers():
    payload = _observation(
        request={
            "method": "GET",
            "url": BASE + PATH,
            "headers": {"User-Agent": "pry/0.1"},
        },
        response={
            "status": 200,
            "headers": {"Retry-After": "1"},
            "body": "x" * (sidecar.BODY_LIMIT * 2),
        },
    )

    result = parse_rate_limit_result(payload, RateLimitConfig(PATH, 10))

    assert result["response"]["headers"] == {"retry-after": "1"}
    assert len(result["response"]["body"]) == sidecar.BODY_LIMIT


@pytest.mark.parametrize(
    "payload",
    [
        [],
        "not a dict",
        None,
        _observation(status="EXPOSED"),
        _observation(status="SAFE"),
        _observation(probe="cors"),
        _observation(evidence=5),
        _observation(count="3"),
        _observation(count=11),
        _observation(statuses="200"),
        _observation(statuses=[200, "200"]),
        _observation(response="nope"),
        _observation(request="nope"),
        _observation(status=OBSERVED, statuses=[200]),
        dict(_observation(), verdict=UNVERIFIED),
        dict(_observation(), proof=None),
    ],
)
def test_a_malformed_payload_is_unverified_and_never_a_verdict(payload):
    result = parse_rate_limit_result(payload, RateLimitConfig(PATH, 10))

    assert isinstance(result, dict)
    assert not isinstance(result, ProbeResult)
    assert set(result) == OBSERVATION_KEYS
    assert result["status"] == UNVERIFIED
    assert RATE_LIMIT_PROBE_INVALID in result["evidence"]
    assert result["count"] == 0
    assert result["statuses"] == []
    assert result["response"] is None
    assert "verdict" not in result
    assert "proof" not in result


def test_validate_rate_limit_honours_a_lower_live_cap():
    config = validate_rate_limit(PATH, 5, max_count=5)
    assert config == RateLimitConfig(endpoint=PATH, count=5)

    with pytest.raises(ProbeError) as exc:
        validate_rate_limit(PATH, 6, max_count=5)
    assert exc.value.cause == RATE_LIMIT_CONFIG_INVALID
    assert "1..5" in exc.value.message


def test_probe_rate_limit_uses_the_requested_spacing():
    result, fetch, sleeps = _run(3, *[_response(200) for _ in range(3)])
    assert sleeps.calls == [0.1, 0.1]

    fetch = FakeFetch(*[_response(200) for _ in range(3)])
    sleeps = Sleeps()
    result = sidecar.probe_rate_limit(
        BASE, PATH, 3, fetch=fetch, sleep=sleeps, spacing=0.5
    )

    assert result["status"] == OBSERVED
    assert sleeps.calls == [0.5, 0.5]
    assert "verdict" not in result
    assert "proof" not in result
