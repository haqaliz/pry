"""Local SSRF config validation and result mapping (AT2, AT4, AT10)."""

import json

import pytest

from pry.probe.results import EXPOSED, NOT_REPRODUCED, UNVERIFIED, ProbeError
from pry.probe.ssrf import (
    SSRF_APP_REQUEST_FAILED,
    SSRF_CONFIG_INVALID,
    SSRF_HIT_READ_FAILED,
    SSRF_PROBE_INVALID,
    SsrfConfig,
    new_nonce,
    parse_ssrf_result,
    redact_headers,
    validate_ssrf,
)

NONCE = "0123456789abcdef0123456789abcdef"
CALLBACK_URL = "http://pry-callback:9000/" + NONCE
APP_URL = "http://app:8000/api/fetch?url=" + (
    "http%3A%2F%2Fpry-callback%3A9000%2F" + NONCE
)
CONFIG = SsrfConfig(endpoint="/api/fetch", parameter="url")
REDACTED = "[redacted]"

COOKIE = "session-cookie-secret"
AUTHORIZATION = "Bearer authorization-secret"
SET_COOKIE = "set-cookie-secret"
API_KEY = "api-key-secret"
CALLBACK_KEY = "callback-api-key-secret"


def _payload(
    hit=True,
    cause=None,
    app_status=200,
    callback_path="/" + NONCE,
    request_headers=None,
    app_headers=None,
    callback_headers=None,
):
    return {
        "hit": hit,
        "cause": cause,
        "request": {
            "method": "GET",
            "url": APP_URL,
            "headers": (
                {"User-Agent": "pry/0.1"}
                if request_headers is None
                else request_headers
            ),
        },
        "app_response": None
        if app_status is None
        else {
            "status": app_status,
            "headers": (
                {"Content-Type": "text/plain"}
                if app_headers is None
                else app_headers
            ),
            "body": "ok",
        },
        "callback_hit": None
        if callback_path is None
        else {
            "method": "GET",
            "path": callback_path,
            "headers": (
                {"User-Agent": "python-urllib"}
                if callback_headers is None
                else callback_headers
            ),
        },
    }


def test_validate_ssrf_accepts_a_path_and_a_token_parameter():
    assert validate_ssrf("/api/fetch", "url") == SsrfConfig(
        endpoint="/api/fetch", parameter="url"
    )
    assert validate_ssrf("/api/fetch/1", "_target.url-2") == SsrfConfig(
        endpoint="/api/fetch/1", parameter="_target.url-2"
    )


@pytest.mark.parametrize(
    "endpoint",
    [
        "http://evil.invalid/fetch",
        "https://evil.invalid/fetch",
        "//evil.invalid",
        "api/fetch",
        "/api fetch",
        "/api/fetch?x=1",
        "/api/fetch#frag",
        "",
        "/" + "a" * 2048,
    ],
)
def test_validate_ssrf_refuses_a_non_path_endpoint(endpoint):
    with pytest.raises(ProbeError) as exc:
        validate_ssrf(endpoint, "url")

    assert exc.value.cause == SSRF_CONFIG_INVALID
    assert "endpoint" in exc.value.message


@pytest.mark.parametrize(
    "parameter",
    [
        "",
        "1url",
        "url name",
        "url&next",
        "url=value",
        "url\n",
        "a" * 65,
        None,
        123,
    ],
)
def test_validate_ssrf_refuses_an_invalid_parameter(parameter):
    with pytest.raises(ProbeError) as exc:
        validate_ssrf("/api/fetch", parameter)

    assert exc.value.cause == SSRF_CONFIG_INVALID
    assert "parameter" in exc.value.message


def test_new_nonce_is_a_fresh_hex_token():
    first = new_nonce()
    second = new_nonce()

    assert len(first) == 32
    assert first != second
    assert all(character in "0123456789abcdef" for character in first)


def test_parse_ssrf_hit_is_exposed_with_the_callback_request():
    result = parse_ssrf_result(_payload(), CONFIG)

    assert result.probe == "ssrf"
    assert result.verdict == EXPOSED
    assert result.cause is None
    assert result.request == {
        "method": "GET",
        "url": APP_URL,
        "headers": {"user-agent": "pry/0.1"},
    }
    assert result.response["status"] == 200
    assert result.response["method"] == "GET"
    assert result.response["path"] == "/" + NONCE
    assert result.response["headers"] == {"user-agent": "python-urllib"}
    assert "status 200" in result.evidence
    assert "/" + NONCE in result.evidence


def test_parse_ssrf_no_hit_with_an_app_response_is_not_reproduced():
    payload = _payload(hit=False, callback_path=None, app_status=204)

    result = parse_ssrf_result(payload, CONFIG)

    assert result.probe == "ssrf"
    assert result.verdict == NOT_REPRODUCED
    assert result.cause is None
    assert result.request["url"] == APP_URL
    assert result.response["status"] == 204
    assert result.response["body"] == "ok"
    assert "204" in result.evidence


@pytest.mark.parametrize(
    "cause", [SSRF_APP_REQUEST_FAILED, SSRF_HIT_READ_FAILED]
)
def test_parse_ssrf_probe_failure_is_unverified_with_the_cause(cause):
    payload = _payload(
        hit=False,
        cause=cause,
        callback_path=None,
        app_status=None if cause == SSRF_APP_REQUEST_FAILED else 200,
    )

    result = parse_ssrf_result(payload, CONFIG)

    assert result.probe == "ssrf"
    assert result.verdict == UNVERIFIED
    assert result.cause == cause
    assert result.request["url"] == APP_URL


@pytest.mark.parametrize(
    "payload",
    [
        None,
        [],
        {},
        {"hit": "yes", "request": _payload()["request"]},
        {"hit": True, "request": _payload()["request"], "callback_hit": None},
        {
            "hit": True,
            "request": _payload()["request"],
            "callback_hit": {"method": "GET"},
        },
        {
            "hit": True,
            "request": _payload()["request"],
            "callback_hit": {"path": "/" + NONCE},
        },
        {
            "hit": True,
            "cause": "SSRF_UNEXPECTED",
            "request": _payload()["request"],
            "callback_hit": _payload()["callback_hit"],
        },
        {"hit": False, "request": _payload()["request"], "cause": None},
        {
            "hit": False,
            "request": _payload()["request"],
            "cause": "SSRF_UNEXPECTED",
            "app_response": _payload()["app_response"],
        },
        {
            "hit": False,
            "request": _payload()["request"],
            "cause": None,
            "app_response": {"headers": {}},
        },
        {"hit": False, "request": "not-an-object", "cause": None},
        {
            "hit": False,
            "request": {"method": "GET"},
            "cause": None,
            "app_response": _payload()["app_response"],
        },
    ],
)
def test_parse_ssrf_malformed_payload_is_unverified(payload):
    result = parse_ssrf_result(payload, CONFIG)

    assert result.probe == "ssrf"
    assert result.verdict == UNVERIFIED
    assert result.cause == SSRF_PROBE_INVALID
    assert result.response is None


def test_parse_ssrf_redacts_stored_credentials_everywhere():
    payload = _payload(
        request_headers={
            "Cookie": COOKIE,
            "Authorization": AUTHORIZATION,
            "User-Agent": "pry/0.1",
        },
        app_headers={
            "Set-Cookie": SET_COOKIE,
            "X-Api-Key": API_KEY,
            "Content-Type": "text/plain",
        },
        callback_headers={
            "api-key": CALLBACK_KEY,
            "User-Agent": "python-urllib",
        },
    )

    result = parse_ssrf_result(payload, CONFIG)
    stored = json.dumps(
        {
            "request": result.request,
            "response": result.response,
            "evidence": result.evidence,
        }
    )

    for secret in (COOKIE, AUTHORIZATION, SET_COOKIE, API_KEY, CALLBACK_KEY):
        assert secret not in stored
    assert result.request["headers"]["cookie"] == REDACTED
    assert result.request["headers"]["authorization"] == REDACTED
    assert result.request["headers"]["user-agent"] == "pry/0.1"
    assert result.response["headers"]["api-key"] == REDACTED
    assert result.response["headers"]["user-agent"] == "python-urllib"
    # The evidence only names the app status and hit path, never a header.
    assert API_KEY not in result.evidence

    miss = parse_ssrf_result(
        _payload(
            hit=False,
            callback_path=None,
            app_headers={
                "Set-Cookie": SET_COOKIE,
                "X-Api-Key": API_KEY,
                "Content-Type": "text/plain",
            },
        ),
        CONFIG,
    )
    assert miss.response["headers"]["set-cookie"] == REDACTED
    assert miss.response["headers"]["x-api-key"] == REDACTED
    assert SET_COOKIE not in json.dumps(miss.response)
    assert API_KEY not in json.dumps(miss.response)


def test_redact_headers_lowercases_and_keeps_non_secret_values():
    headers = redact_headers(
        {
            "Cookie": COOKIE,
            "Authorization": AUTHORIZATION,
            "Set-Cookie": SET_COOKIE,
            "X-Api-Key": API_KEY,
            "Content-Type": "text/plain",
        }
    )

    assert headers == {
        "cookie": REDACTED,
        "authorization": REDACTED,
        "set-cookie": REDACTED,
        "x-api-key": REDACTED,
        "content-type": "text/plain",
    }
    assert redact_headers(None) == {}


def test_parse_ssrf_hit_without_an_app_response_still_names_the_hit_path():
    payload = _payload(hit=True, app_status=None)

    result = parse_ssrf_result(payload, CONFIG)

    assert result.verdict == EXPOSED
    assert "/" + NONCE in result.evidence
