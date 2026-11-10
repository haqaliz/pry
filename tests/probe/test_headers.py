"""Response header observation parser tests (AT1-AT3, AT5).

A header observation is hardening evidence, never a verdict or a proof.
"""

import pytest

from pry.probe.headers import (
    HEADER_PROBE,
    HEADERS_PROBE_INVALID,
    OBSERVED,
    RECOMMENDED_HEADERS,
    parse_headers_result,
)
from pry.probe.results import BODY_LIMIT, UNVERIFIED, ProbeResult

BASE = "http://app:3000/"
OBSERVATION_KEYS = {
    "probe",
    "status",
    "evidence",
    "request",
    "response",
    "missing",
    "present",
}


def _observation(status=OBSERVED, **overrides):
    observation = {
        "probe": HEADER_PROBE,
        "status": status,
        "evidence": "6 recommended response headers checked on /: 4 "
        "present, 2 missing (hardening observation)",
        "request": {
            "method": "GET",
            "url": BASE,
            "headers": {"User-Agent": "pry/0.1"},
        },
        "response": {
            "status": 200,
            "headers": {"X-Frame-Options": "DENY"},
            "body": "ok",
        },
        "missing": ["content-security-policy", "permissions-policy"],
        "present": ["x-frame-options", "x-content-type-options"],
    }
    observation.update(overrides)
    return observation


def _unverified_observation():
    return _observation(
        status=UNVERIFIED,
        evidence="TARGET_UNREACHABLE: transport failure: connection refused",
        response=None,
        missing=[],
        present=[],
    )


def test_recommended_headers_exclude_hsts():
    assert RECOMMENDED_HEADERS == (
        "content-security-policy",
        "x-content-type-options",
        "x-frame-options",
        "referrer-policy",
        "permissions-policy",
        "cross-origin-opener-policy",
    )


@pytest.mark.parametrize("status", [OBSERVED, UNVERIFIED])
def test_parse_headers_result_passes_a_valid_observation_through(status):
    payload = (
        _observation(status)
        if status == OBSERVED
        else _unverified_observation()
    )

    result = parse_headers_result(payload)

    assert isinstance(result, dict)
    assert not isinstance(result, ProbeResult)
    assert set(result) == OBSERVATION_KEYS
    assert result["status"] == status
    assert result["probe"] == HEADER_PROBE
    assert result["evidence"] == payload["evidence"]
    assert result["missing"] == payload["missing"]
    assert result["present"] == payload["present"]
    assert "verdict" not in result
    assert "proof" not in result


def test_parse_headers_result_lowercases_names_and_caps_the_body():
    payload = _observation(
        request={
            "method": "GET",
            "url": BASE,
            "headers": {"User-Agent": "pry/0.1"},
        },
        response={
            "status": 200,
            "headers": {"X-Frame-Options": "DENY"},
            "body": "x" * (BODY_LIMIT * 2),
        },
        missing=["Content-Security-Policy"],
        present=["X-Frame-Options"],
    )

    result = parse_headers_result(payload)

    assert result["request"]["headers"] == {"user-agent": "pry/0.1"}
    assert result["response"]["headers"] == {"x-frame-options": "DENY"}
    assert len(result["response"]["body"]) == BODY_LIMIT
    assert result["missing"] == ["content-security-policy"]
    assert result["present"] == ["x-frame-options"]


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
        _observation(evidence=""),
        _observation(request="nope"),
        _observation(request={"method": "GET"}),
        _observation(request={"method": "GET", "url": BASE, "headers": []}),
        _observation(response="nope"),
        _observation(response={"status": "200", "headers": {}}),
        _observation(response={"status": True, "headers": {}}),
        _observation(response={"status": 200, "headers": []}),
        _observation(status=OBSERVED, response=None),
        _observation(missing="content-security-policy"),
        _observation(missing=[1]),
        _observation(present="x-frame-options"),
        _observation(present=[1]),
        _observation(status=UNVERIFIED, response=None, missing=["x"]),
        dict(_observation(), verdict=UNVERIFIED),
        dict(_observation(), proof=None),
    ],
)
def test_a_malformed_payload_is_unverified_and_never_a_verdict(payload):
    result = parse_headers_result(payload)

    assert isinstance(result, dict)
    assert not isinstance(result, ProbeResult)
    assert set(result) == OBSERVATION_KEYS
    assert result["status"] == UNVERIFIED
    assert HEADERS_PROBE_INVALID in result["evidence"]
    assert result["response"] is None
    assert result["missing"] == []
    assert result["present"] == []
    assert "verdict" not in result
    assert "proof" not in result
