"""Live SSRF with a user callback: validation and probe verdicts (AT1-AT5, AT7).

Every request is scripted; nothing in this file sends traffic.
"""

import urllib.parse

import pytest

from pry.probe.live_ssrf import (
    LIVE_SSRF_CALLBACK_LIMIT,
    SSRF_CALLBACK_INVALID,
    SSRF_CALLBACK_REQUIRED,
    LiveSsrfConfig,
    probe_live_ssrf,
    validate_live_ssrf,
)
from pry.probe.results import (
    BODY_LIMIT,
    EXPOSED,
    NOT_REPRODUCED,
    UNVERIFIED,
    ProbeError,
    ProbeResult,
)
from pry.probe.sidecar import Response, TransportError

BASE = "https://app.example.com"
CALLBACK = "https://callback.example/pry"
HEADERS = {"User-Agent": "pry/0.1"}


def _config(callback=CALLBACK):
    return LiveSsrfConfig(
        endpoint="/api/fetch", parameter="url", callback_url=callback
    )


def _response(status, body="", headers=None, final_url=None):
    return Response(status, headers or {}, body, final_url or "")


class ScriptedFetch:
    def __init__(self, *responses):
        self.responses = list(responses)
        self.calls = []

    def __call__(self, method, url, headers, body=None):
        self.calls.append((method, url, dict(headers)))
        value = self.responses.pop(0)
        if isinstance(value, Exception):
            raise value
        return Response(
            value.status, value.headers, value.body, value.final_url or url
        )

    def urls(self):
        return [url for _method, url, _headers in self.calls]


def _run(*responses, config=None):
    fetch = ScriptedFetch(*responses)
    sleeps = []
    payload = probe_live_ssrf(
        BASE, config or _config(), fetch=fetch, sleep=sleeps.append
    )
    return ProbeResult(**payload), fetch, sleeps


def _callback_of(fetch):
    url = fetch.urls()[0]
    query = urllib.parse.parse_qs(urllib.parse.urlsplit(url).query)
    return query["url"][0]


# --- validation -----------------------------------------------------------


def test_validate_accepts_an_https_callback_with_a_trailing_slash():
    config = validate_live_ssrf("/api/fetch", "url", CALLBACK + "/")

    assert config == _config()


@pytest.mark.parametrize(
    "callback",
    (
        "http://127.0.0.1:9000",
        "http://localhost:9000/pry",
        "http://[::1]:9000",
    ),
)
def test_validate_accepts_plain_http_only_on_loopback(callback):
    assert validate_live_ssrf("/api/fetch", "url", callback).callback_url == (
        callback
    )


@pytest.mark.parametrize(
    "callback",
    (
        "http://callback.example/pry",
        "https://user:secret@callback.example/pry",
        "https://callback.example/pry?nonce=1",
        "https://callback.example/pry#fragment",
        "https://callback.example/pry path",
        "ftp://callback.example/pry",
        "https://callback.example:notaport/pry",
        "callback.example/pry",
        "",
        "https://callback.example/" + "a" * LIVE_SSRF_CALLBACK_LIMIT,
    ),
)
def test_validate_rejects_a_bad_callback(callback):
    with pytest.raises(ProbeError) as exc:
        validate_live_ssrf("/api/fetch", "url", callback)

    assert exc.value.cause == SSRF_CALLBACK_INVALID


def test_validate_requires_a_callback_url():
    with pytest.raises(ProbeError) as exc:
        validate_live_ssrf("/api/fetch", "url", None)

    assert exc.value.cause == SSRF_CALLBACK_REQUIRED


@pytest.mark.parametrize(
    "endpoint,parameter",
    (
        ("http://evil.invalid/fetch", "url"),
        ("api/fetch", "url"),
        ("/api/fetch", "1url"),
        ("/api/fetch", "url name"),
    ),
)
def test_validate_reuses_the_local_endpoint_and_parameter_rules(
    endpoint, parameter
):
    with pytest.raises(ProbeError) as exc:
        validate_live_ssrf(endpoint, parameter, CALLBACK)

    assert exc.value.cause == "SSRF_CONFIG_INVALID"


# --- probe verdicts -------------------------------------------------------


def test_a_callback_hit_is_exposed_with_both_pairs():
    result, fetch, sleeps = _run(
        _response(200), _response(404), _response(200)
    )
    callback_url = _callback_of(fetch)
    nonce = callback_url.rsplit("/", 1)[1]

    assert result.probe == "ssrf"
    assert result.verdict == EXPOSED
    assert result.cause is None
    assert result.evidence == (
        "callback recorded GET /%s on poll 2/3 after app returned status 200"
        % nonce
    )
    assert len(nonce) == 32
    assert result.request["url"] == BASE + "/api/fetch?" + urllib.parse.urlencode(
        {"url": callback_url}
    )
    assert result.request["headers"] == {"user-agent": "pry/0.1"}
    assert result.response["status"] == 200
    assert result.response["callback"] == {
        "request": {
            "method": "GET",
            "url": callback_url,
            "headers": {"user-agent": "pry/0.1"},
        },
        "response": {"status": 200, "headers": {}, "body": ""},
        "attempts": 2,
    }
    assert sleeps == [0.5, 0.5]
    assert [call[0] for call in fetch.calls] == ["GET", "GET", "GET"]


def test_a_hit_on_the_third_poll_is_still_exposed():
    result, fetch, sleeps = _run(
        _response(200), _response(404), _response(404), _response(200)
    )
    nonce = _callback_of(fetch).rsplit("/", 1)[1]

    assert result.verdict == EXPOSED
    assert result.evidence == (
        "callback recorded GET /%s on poll 3/3 after app returned status 200"
        % nonce
    )
    assert result.response["callback"]["attempts"] == 3
    assert sleeps == [0.5, 0.5, 0.5]


def test_no_callback_hit_is_not_reproduced():
    result, _fetch, sleeps = _run(
        _response(200), _response(404), _response(404), _response(404)
    )

    assert result.verdict == NOT_REPRODUCED
    assert result.cause is None
    assert result.evidence == (
        "app responded status 200 but callback recorded no hit after 3 polls"
    )
    assert result.response["status"] == 200
    assert result.response["callback"]["response"]["status"] == 404
    assert result.response["callback"]["attempts"] == 3
    assert sleeps == [0.5, 0.5, 0.5]


@pytest.mark.parametrize("status", (401, 403, 404))
def test_a_rejected_app_request_is_not_reproduced_without_polls(status):
    result, fetch, sleeps = _run(_response(status))

    assert result.verdict == NOT_REPRODUCED
    assert result.response["status"] == status
    assert "callback" not in result.response
    assert len(fetch.calls) == 1
    assert sleeps == []


@pytest.mark.parametrize("status", (302, 500, 503))
def test_a_non_2xx_app_response_is_unverified(status):
    result, fetch, sleeps = _run(_response(status))

    assert result.verdict == UNVERIFIED
    assert result.cause is None
    assert result.response["status"] == status
    assert "callback" not in result.response
    assert len(fetch.calls) == 1
    assert sleeps == []


def test_a_foreign_final_origin_is_not_reproduced_without_polls():
    result, fetch, sleeps = _run(
        _response(200, final_url="https://other.example/fetch")
    )

    assert result.verdict == NOT_REPRODUCED
    assert result.response["status"] == 200
    assert "callback" not in result.response
    assert len(fetch.calls) == 1
    assert sleeps == []


def test_an_app_transport_failure_is_unverified():
    result, fetch, sleeps = _run(
        TransportError("TARGET_UNREACHABLE", "connection refused")
    )

    assert result.verdict == UNVERIFIED
    assert result.cause == "TARGET_UNREACHABLE"
    assert result.response is None
    assert len(fetch.calls) == 1
    assert sleeps == []


def test_a_callback_transport_failure_is_unverified():
    result, _fetch, sleeps = _run(
        _response(200),
        TransportError("REQUEST_TIMEOUT", "callback timed out"),
    )

    assert result.verdict == UNVERIFIED
    assert result.cause == "REQUEST_TIMEOUT"
    assert result.response["status"] == 200
    assert result.response["callback"]["response"] is None
    assert result.response["callback"]["attempts"] == 1
    assert sleeps == [0.5]


@pytest.mark.parametrize("status", (500, 502))
def test_a_callback_service_error_is_unverified(status):
    result, _fetch, _sleeps = _run(_response(200), _response(status))

    assert result.verdict == UNVERIFIED
    assert result.cause is None
    assert result.response["callback"]["response"]["status"] == status
    assert result.response["callback"]["attempts"] == 1


def test_no_auth_or_cookies_are_sent():
    _result, fetch, _sleeps = _run(_response(200), _response(200))

    assert [headers for _m, _u, headers in fetch.calls] == [HEADERS, HEADERS]


def test_response_headers_are_redacted_and_the_body_is_capped():
    result, _fetch, _sleeps = _run(
        _response(
            200,
            "x" * (BODY_LIMIT + 10),
            {
                "Set-Cookie": "sid=app",
                "Cookie": "sid=app",
                "Authorization": "Bearer app",
                "Proxy-Authorization": "Basic app",
                "X-Api-Key": "app-key",
                "Api-Key": "app-key",
                "Content-Type": "text/plain",
            },
        ),
        _response(
            200, "hit", {"Authorization": "Bearer cb", "X-Api-Key": "cb-key"}
        ),
    )

    assert result.response["headers"] == {
        "set-cookie": "[redacted]",
        "cookie": "[redacted]",
        "authorization": "[redacted]",
        "proxy-authorization": "[redacted]",
        "x-api-key": "[redacted]",
        "api-key": "[redacted]",
        "content-type": "text/plain",
    }
    assert len(result.response["body"]) == BODY_LIMIT
    assert result.response["callback"]["response"]["headers"] == {
        "authorization": "[redacted]",
        "x-api-key": "[redacted]",
    }


def test_each_run_uses_a_fresh_nonce():
    _first, fetch_one, _sleeps = _run(_response(404))
    _second, fetch_two, _sleeps = _run(_response(404))

    first = _callback_of(fetch_one)
    second = _callback_of(fetch_two)
    assert first != second
    assert first.rsplit("/", 1)[1] != second.rsplit("/", 1)[1]
