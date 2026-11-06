"""Read-only probe sidecar decision tests (AT1-AT6).

Every probe takes an injected ``fetch``; nothing here opens a socket.
"""

import ast
import io
import json
import socket
import urllib.error
from pathlib import Path

import pytest

import pry.probe.sidecar as sidecar
from pry.probe.results import ProbeResult

BASE = "http://app:3000"
ENV = (
    "APP_ENV=production\n"
    "DATABASE_URL=postgres://user:pass@db.local/app\n"
    "DEBUG=false\n"
)
TRACEBACK = (
    "Traceback (most recent call last):\n"
    '  File "/app/server.py", line 42, in handler\n'
    '    raise ValueError("boom")\n'
    "ValueError: boom\n"
)
SQL_ERROR = (
    "You have an error in your SQL syntax; check the manual that corresponds "
    "to your MySQL server version near \"'\" at line 1"
)


def _response(status=200, headers=None, body="", path="/"):
    return sidecar.Response(status, headers or {}, body, BASE + path)


def _all(status=404, body="", headers=None):
    return [_response(status, headers, body, path) for path in sidecar.SECRET_PATHS]


class FakeFetch:
    """Records each request and returns scripted responses or raises."""

    def __init__(self, *responses):
        self.responses = list(responses)
        self.calls = []

    def __call__(self, method, url, headers):
        self.calls.append((method, url, dict(headers)))
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response


class FakeHTTPResponse:
    def __init__(self, status=200, headers=None, body=b"", url=BASE + "/"):
        self.status = status
        self.headers = headers or {}
        self.body = body
        self.url = url
        self.closed = False

    def read(self, size):
        return self.body[:size]

    def geturl(self):
        return self.url

    def close(self):
        self.closed = True


class FakeOpener:
    def __init__(self, response=None, error=None):
        self.response = response
        self.error = error
        self.request = None
        self.timeout = None

    def open(self, request, timeout):
        self.request = request
        self.timeout = timeout
        if self.error is not None:
            raise self.error
        return self.response


def test_cors_reflected_origin_with_credentials_is_exposed():
    fetch = FakeFetch(
        _response(
            200,
            {
                "Access-Control-Allow-Origin": sidecar.ORIGIN,
                "Access-Control-Allow-Credentials": "true",
            },
        )
    )

    result = sidecar.probe_cors(BASE, fetch=fetch)

    assert result["probe"] == "cors"
    assert result["verdict"] == sidecar.EXPOSED
    assert result["cause"] is None
    assert sidecar.ORIGIN in result["evidence"]
    assert fetch.calls == [
        (
            "GET",
            BASE + "/",
            {"Origin": sidecar.ORIGIN, "User-Agent": sidecar.USER_AGENT},
        )
    ]
    assert result["request"] == {
        "method": "GET",
        "url": BASE + "/",
        "headers": {
            "origin": sidecar.ORIGIN,
            "user-agent": sidecar.USER_AGENT,
        },
    }
    assert result["response"]["headers"] == {
        "access-control-allow-origin": sidecar.ORIGIN,
        "access-control-allow-credentials": "true",
    }


def test_cors_reflected_origin_without_credentials_is_not_reproduced():
    fetch = FakeFetch(
        _response(200, {"Access-Control-Allow-Origin": sidecar.ORIGIN})
    )

    result = sidecar.probe_cors(BASE, fetch=fetch)

    assert result["verdict"] == sidecar.NOT_REPRODUCED
    assert "credentials" in result["evidence"].lower()


def test_cors_wildcard_with_credentials_is_not_reproduced():
    fetch = FakeFetch(
        _response(
            200,
            {
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Credentials": "true",
            },
        )
    )

    result = sidecar.probe_cors(BASE, fetch=fetch)

    assert result["verdict"] == sidecar.NOT_REPRODUCED
    assert "*" in result["evidence"]


def test_cors_without_allow_origin_is_not_reproduced():
    fetch = FakeFetch(_response(200, {}))

    result = sidecar.probe_cors(BASE, fetch=fetch)

    assert result["verdict"] == sidecar.NOT_REPRODUCED
    assert "Access-Control-Allow-Origin" in result["evidence"]


def test_errors_stack_trace_is_exposed():
    fetch = FakeFetch(
        _response(500, {"Content-Type": "text/plain"}, TRACEBACK, "/__pry_missing__?id=%27")
    )

    result = sidecar.probe_errors(BASE, fetch=fetch)

    assert result["probe"] == "errors"
    assert result["verdict"] == sidecar.EXPOSED
    assert "traceback" in result["evidence"].lower()
    assert fetch.calls == [
        (
            "GET",
            BASE + "/__pry_missing__?id=%27",
            {"User-Agent": sidecar.USER_AGENT},
        )
    ]
    assert result["request"]["headers"] == {"user-agent": sidecar.USER_AGENT}


def test_errors_sql_error_is_exposed():
    fetch = FakeFetch(_response(500, {}, SQL_ERROR, "/__pry_missing__?id=%27"))

    result = sidecar.probe_errors(BASE, fetch=fetch)

    assert result["verdict"] == sidecar.EXPOSED
    assert "sql" in result["evidence"].lower()


def test_errors_generic_404_is_not_reproduced():
    fetch = FakeFetch(
        _response(
            404,
            {"Content-Type": "text/html"},
            "<!doctype html><h1>404 Not Found</h1>",
            "/__pry_missing__?id=%27",
        )
    )

    result = sidecar.probe_errors(BASE, fetch=fetch)

    assert result["verdict"] == sidecar.NOT_REPRODUCED
    assert result["cause"] is None


def test_errors_requires_an_error_status():
    fetch = FakeFetch(
        _response(200, {}, TRACEBACK, "/__pry_missing__?id=%27")
    )

    result = sidecar.probe_errors(BASE, fetch=fetch)

    assert result["verdict"] == sidecar.NOT_REPRODUCED
    assert "status" in result["evidence"]


def test_secrets_env_with_a_secret_is_exposed_and_redacted():
    fetch = FakeFetch(_response(200, {"Content-Type": "text/plain"}, ENV, "/.env"))

    result = sidecar.probe_secrets(BASE, fetch=fetch)

    body = result["response"]["body"]
    assert result["probe"] == "secrets"
    assert result["verdict"] == sidecar.EXPOSED
    assert "DATABASE_URL" in result["evidence"]
    assert "/.env" in result["evidence"]
    assert "DATABASE_URL=[redacted]" in body
    assert "user:pass" not in body
    assert "postgres://" not in body
    assert "APP_ENV=production" in body
    assert fetch.calls[0][1] == BASE + "/.env"
    assert len(fetch.calls) == 1


def test_secrets_env_404_is_not_reproduced():
    fetch = FakeFetch(*_all(404))

    result = sidecar.probe_secrets(BASE, fetch=fetch)

    assert result["verdict"] == sidecar.NOT_REPRODUCED
    assert result["cause"] is None
    assert [url for _, url, _ in fetch.calls] == [
        BASE + path for path in sidecar.SECRET_PATHS
    ]


def test_secrets_200_without_a_secret_is_not_reproduced():
    public = "APP_NAME=pry\nDEBUG=false\nPORT=3000\n"
    fetch = FakeFetch(*_all(200, public))

    result = sidecar.probe_secrets(BASE, fetch=fetch)

    assert result["verdict"] == sidecar.NOT_REPRODUCED
    assert "no secret" in result["evidence"]


def test_secrets_redirect_is_not_reproduced_and_not_followed():
    fetch = FakeFetch(*_all(302, "", {"Location": "https://evil.invalid/.env"}))

    result = sidecar.probe_secrets(BASE, fetch=fetch)

    assert result["verdict"] == sidecar.NOT_REPRODUCED
    assert all(url.startswith(BASE + "/") for _, url, _ in fetch.calls)
    assert result["response"]["status"] == 302


def test_secrets_cross_origin_200_is_not_reproduced_and_still_redacted():
    cross_origin = sidecar.Response(200, {}, ENV, "https://evil.invalid/.env")
    fetch = FakeFetch(cross_origin, *_all(404)[1:])

    result = sidecar.probe_secrets(BASE, fetch=fetch)

    assert result["verdict"] == sidecar.NOT_REPRODUCED
    assert "user:pass" not in result["response"]["body"]
    assert "[redacted]" in result["response"]["body"]


@pytest.mark.parametrize(
    "probe", [sidecar.probe_cors, sidecar.probe_errors, sidecar.probe_secrets]
)
def test_transport_failure_is_unverified_with_a_named_cause(probe):
    fetch = FakeFetch(
        sidecar.TransportError(sidecar.TARGET_UNREACHABLE, "connection refused")
    )

    result = probe(BASE, fetch=fetch)

    assert result["verdict"] == sidecar.UNVERIFIED
    assert result["cause"] == sidecar.TARGET_UNREACHABLE
    assert result["response"] is None
    assert "Traceback" not in result["evidence"]


def test_result_shape_loads_as_the_host_probe_result():
    fetch = FakeFetch(
        _response(
            200,
            {
                "Access-Control-Allow-Origin": sidecar.ORIGIN,
                "Access-Control-Allow-Credentials": "true",
            },
        )
    )

    result = sidecar.probe_cors(BASE, fetch=fetch)
    host = ProbeResult(**result)

    assert set(result) == {
        "probe",
        "verdict",
        "cause",
        "evidence",
        "request",
        "response",
    }
    assert set(result["request"]) == {"method", "url", "headers"}
    assert set(result["response"]) == {"status", "headers", "body"}
    assert host.probe == "cors"
    assert host.verdict == sidecar.EXPOSED


def test_urllib_fetch_caps_the_body_at_4_kib_and_lowercases_headers():
    fake = FakeOpener(
        FakeHTTPResponse(
            200,
            {"Content-Type": "text/plain", "X-Test": "1"},
            b"x" * (sidecar.BODY_LIMIT * 3),
            BASE + "/",
        )
    )

    response = sidecar.urllib_fetch(
        "GET", BASE + "/", {"User-Agent": sidecar.USER_AGENT}, opener=fake
    )

    assert response.status == 200
    assert response.body == "x" * sidecar.BODY_LIMIT
    assert sidecar.BODY_LIMIT == 4096
    assert response.headers == {"content-type": "text/plain", "x-test": "1"}
    assert response.final_url == BASE + "/"
    assert fake.timeout == sidecar.TIMEOUT == 5
    assert fake.request.get_method() == "GET"


def test_urllib_fetch_returns_http_errors_as_responses():
    error = urllib.error.HTTPError(
        BASE + "/.env",
        404,
        "Not Found",
        {"Content-Type": "text/plain"},
        io.BytesIO(b"missing"),
    )
    fake = FakeOpener(error=error)

    response = sidecar.urllib_fetch("GET", BASE + "/.env", {}, opener=fake)

    assert response.status == 404
    assert response.body == "missing"
    assert response.headers == {"content-type": "text/plain"}


def test_urllib_fetch_maps_a_timeout_to_a_named_cause():
    fake = FakeOpener(error=urllib.error.URLError(socket.timeout("timed out")))

    with pytest.raises(sidecar.TransportError) as exc:
        sidecar.urllib_fetch("GET", BASE + "/", {}, opener=fake)

    assert exc.value.cause == sidecar.REQUEST_TIMEOUT


def test_urllib_fetch_maps_a_refused_connection_to_a_named_cause():
    fake = FakeOpener(
        error=urllib.error.URLError(ConnectionRefusedError(61, "refused"))
    )

    with pytest.raises(sidecar.TransportError) as exc:
        sidecar.urllib_fetch("GET", BASE + "/", {}, opener=fake)

    assert exc.value.cause == sidecar.TARGET_UNREACHABLE


def test_the_fetch_opener_disables_redirects():
    handler = sidecar._NoRedirect()

    assert (
        handler.redirect_request(None, None, 302, "Found", {}, "https://evil.invalid/")
        is None
    )


def test_main_prints_one_json_object_and_returns_zero(capsys):
    fetch = FakeFetch(
        _response(
            200,
            {
                "Access-Control-Allow-Origin": sidecar.ORIGIN,
                "Access-Control-Allow-Credentials": "true",
            },
        )
    )

    code = sidecar.main(["cors", BASE], fetch=fetch)
    captured = capsys.readouterr()

    assert code == 0
    assert captured.err == ""
    assert captured.out.count("\n") == 1
    payload = json.loads(captured.out)
    assert payload["probe"] == "cors"
    assert payload["verdict"] == sidecar.EXPOSED


def test_main_reports_a_transport_failure_as_unverified_json(capsys):
    fetch = FakeFetch(
        sidecar.TransportError(sidecar.REQUEST_TIMEOUT, "timed out")
    )

    code = sidecar.main(["errors", BASE], fetch=fetch)
    captured = capsys.readouterr()

    assert code == 0
    payload = json.loads(captured.out)
    assert payload["verdict"] == sidecar.UNVERIFIED
    assert payload["cause"] == sidecar.REQUEST_TIMEOUT
    assert "Traceback" not in captured.err


def test_main_rejects_an_unknown_probe(capsys):
    code = sidecar.main(["idor", BASE], fetch=FakeFetch())
    captured = capsys.readouterr()

    assert code == 2
    assert captured.out == ""
    assert "usage" in captured.err.lower()


def test_main_rejects_missing_arguments(capsys):
    code = sidecar.main(["cors"], fetch=FakeFetch())
    captured = capsys.readouterr()

    assert code == 2
    assert captured.out == ""
    assert "usage" in captured.err.lower()


def test_sidecar_is_standard_library_only():
    source = Path(sidecar.__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)
    imported = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            imported.append(node.module or "")

    assert imported
    assert not any(
        name == "pry" or name.startswith("pry.") for name in imported
    ), imported
