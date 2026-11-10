"""Read-only probe sidecar decision tests (AT1-AT6).

Every probe takes an injected ``fetch``; nothing here opens a socket.
"""

import ast
import io
import json
import os
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


def test_secrets_redacts_every_secret_in_the_body():
    body = (
        "DATABASE_URL=postgres://user:pass@db.local/app\n"
        "SECRET_KEY=supersecretvalue123\n"
        "APP_ENV=production\n"
    )
    fetch = FakeFetch(_response(200, {}, body, "/.env"))

    result = sidecar.probe_secrets(BASE, fetch=fetch)

    out = result["response"]["body"]
    assert result["verdict"] == sidecar.EXPOSED
    assert "supersecretvalue123" not in out
    assert "user:pass" not in out
    assert "SECRET_KEY=[redacted]" in out
    assert "APP_ENV=production" in out


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


def test_database_is_a_sidecar_probe():
    assert sidecar.PROBES["database"] is sidecar.probe_database


def test_main_accepts_database(capsys):
    fetch = FakeFetch(
        _response(200, body="SQLite format 3\x00rest", path="/data.db")
    )

    code = sidecar.main(["database", BASE], fetch=fetch)
    captured = capsys.readouterr()

    assert code == 0
    assert captured.err == ""
    assert captured.out.count("\n") == 1
    payload = json.loads(captured.out)
    assert payload["probe"] == "database"
    assert payload["verdict"] == sidecar.EXPOSED
    assert fetch.calls[0][1] == BASE + "/data.db"


def test_main_rejects_database_with_the_wrong_argument_count(capsys):
    for argv in (["database"], ["database", BASE, "/extra"]):
        code = sidecar.main(argv, fetch=FakeFetch())
        captured = capsys.readouterr()

        assert code == 2
        assert captured.out == ""
        assert "usage" in captured.err.lower()
        assert "database" in captured.err


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


ENDPOINT = "/api/users"


def _unauth_response(status=200, headers=None, body="", path=ENDPOINT):
    return sidecar.Response(status, headers or {}, body, BASE + path)


def test_unauth_200_json_without_credentials_is_exposed():
    fetch = FakeFetch(
        _unauth_response(
            200,
            {"Content-Type": "application/json; charset=utf-8"},
            '{"users": [{"id": 1}]}',
        )
    )

    result = sidecar.probe_unauth(BASE, ENDPOINT, fetch=fetch)

    assert result["probe"] == "unauth"
    assert result["verdict"] == sidecar.EXPOSED
    assert result["cause"] is None
    assert ENDPOINT in result["evidence"]
    assert "200" in result["evidence"]
    assert "application/json" in result["evidence"]
    assert fetch.calls == [
        ("GET", BASE + ENDPOINT, {"User-Agent": sidecar.USER_AGENT})
    ]
    assert result["request"] == {
        "method": "GET",
        "url": BASE + ENDPOINT,
        "headers": {"user-agent": sidecar.USER_AGENT},
    }
    assert set(result["request"]["headers"]) == {"user-agent"}
    assert len(fetch.calls) == 1


def test_unauth_json_looking_body_without_a_json_content_type_is_exposed():
    fetch = FakeFetch(
        _unauth_response(
            200, {"Content-Type": "text/plain"}, '  [{"id": 1}]'
        )
    )

    result = sidecar.probe_unauth(BASE, ENDPOINT, fetch=fetch)

    assert result["verdict"] == sidecar.EXPOSED
    assert ENDPOINT in result["evidence"]


def test_unauth_empty_json_body_is_not_reproduced():
    fetch = FakeFetch(
        _unauth_response(200, {"Content-Type": "application/json"}, "")
    )

    result = sidecar.probe_unauth(BASE, ENDPOINT, fetch=fetch)

    assert result["verdict"] == sidecar.NOT_REPRODUCED
    assert "empty" in result["evidence"].lower()


@pytest.mark.parametrize("status", [401, 403, 404])
def test_unauth_rejected_statuses_are_not_reproduced(status):
    fetch = FakeFetch(
        _unauth_response(
            status, {"Content-Type": "application/json"}, '{"error": "no"}'
        )
    )

    result = sidecar.probe_unauth(BASE, ENDPOINT, fetch=fetch)

    assert result["verdict"] == sidecar.NOT_REPRODUCED
    assert ENDPOINT in result["evidence"]
    assert str(status) in result["evidence"]


def test_unauth_200_html_login_page_is_not_reproduced():
    fetch = FakeFetch(
        _unauth_response(
            200,
            {"Content-Type": "text/html; charset=utf-8"},
            "<!doctype html><form>login</form>",
        )
    )

    result = sidecar.probe_unauth(BASE, ENDPOINT, fetch=fetch)

    assert result["verdict"] == sidecar.NOT_REPRODUCED
    assert "login page" in result["evidence"].lower()


def test_unauth_500_is_unverified():
    fetch = FakeFetch(_unauth_response(500, {}, "boom"))

    result = sidecar.probe_unauth(BASE, ENDPOINT, fetch=fetch)

    assert result["verdict"] == sidecar.UNVERIFIED
    assert result["response"]["status"] == 500


def test_unauth_transport_failure_is_unverified_with_a_named_cause():
    fetch = FakeFetch(
        sidecar.TransportError(sidecar.REQUEST_TIMEOUT, "timed out")
    )

    result = sidecar.probe_unauth(BASE, ENDPOINT, fetch=fetch)

    assert result["verdict"] == sidecar.UNVERIFIED
    assert result["cause"] == sidecar.REQUEST_TIMEOUT
    assert result["response"] is None
    assert len(fetch.calls) == 1


@pytest.mark.parametrize(
    "path",
    [
        "http://evil.invalid",
        "https://evil.invalid/api",
        "//evil.invalid",
        "api/users",
        "",
        "/api users",
        "/api\tusers",
        "/api\nusers",
        "/api\x00users",
        "/" + "a" * 2048,
    ],
)
def test_unauth_invalid_paths_are_refused_before_any_fetch(path):
    fetch = FakeFetch()

    result = sidecar.probe_unauth(BASE, path, fetch=fetch)

    assert result["probe"] == "unauth"
    assert result["verdict"] == sidecar.UNVERIFIED
    assert result["cause"] == sidecar.INVALID_ENDPOINT
    assert result["response"] is None
    assert "path" in result["evidence"].lower()
    assert fetch.calls == []


def test_unauth_accepts_a_path_at_the_length_limit():
    path = "/" + "a" * 2047
    fetch = FakeFetch(_unauth_response(404, {}, "missing", path))

    result = sidecar.probe_unauth(BASE, path, fetch=fetch)

    assert result["verdict"] == sidecar.NOT_REPRODUCED
    assert fetch.calls[0][1] == BASE + path


def test_unauth_caps_the_captured_body_and_lowercases_headers():
    body = '{"data": "' + "x" * (sidecar.BODY_LIMIT * 2) + '"}'
    fetch = FakeFetch(
        _unauth_response(200, {"Content-Type": "Application/JSON"}, body)
    )

    result = sidecar.probe_unauth(BASE, ENDPOINT, fetch=fetch)

    assert result["verdict"] == sidecar.EXPOSED
    assert len(result["response"]["body"]) == sidecar.BODY_LIMIT
    assert result["response"]["headers"] == {"content-type": "Application/JSON"}
    assert result["request"]["headers"] == {"user-agent": sidecar.USER_AGENT}


def test_main_accepts_unauth_with_a_path(capsys):
    fetch = FakeFetch(
        _unauth_response(
            200, {"Content-Type": "application/json"}, '{"id": 1}'
        )
    )

    code = sidecar.main(["unauth", BASE, ENDPOINT], fetch=fetch)
    captured = capsys.readouterr()

    assert code == 0
    assert captured.err == ""
    payload = json.loads(captured.out)
    assert payload["probe"] == "unauth"
    assert payload["verdict"] == sidecar.EXPOSED
    assert fetch.calls[0][1] == BASE + ENDPOINT


def test_main_prints_an_invalid_endpoint_as_unverified_json(capsys):
    code = sidecar.main(["unauth", BASE, "http://evil.invalid"], fetch=FakeFetch())
    captured = capsys.readouterr()

    assert code == 0
    payload = json.loads(captured.out)
    assert payload["verdict"] == sidecar.UNVERIFIED
    assert payload["cause"] == sidecar.INVALID_ENDPOINT


@pytest.mark.parametrize(
    "argv",
    [
        ["unauth", BASE],
        ["unauth", BASE, ENDPOINT, "/extra"],
        ["cors", BASE, ENDPOINT],
        ["idor", BASE, ENDPOINT],
        ["rate_limit", BASE],
        ["rate_limit", BASE, ENDPOINT],
        ["rate_limit", BASE, ENDPOINT, "10", "/extra"],
        ["rate_limit", BASE, ENDPOINT, "ten"],
    ],
)
def test_main_rejects_invalid_argv_for_the_new_probe(argv, capsys):
    code = sidecar.main(argv, fetch=FakeFetch())
    captured = capsys.readouterr()

    assert code == 2
    assert captured.out == ""
    assert "usage" in captured.err.lower()


def test_main_accepts_rate_limit_with_a_count(capsys):
    fetch = FakeFetch(*[_response(200) for _ in range(3)])

    code = sidecar.main(
        ["rate_limit", BASE, ENDPOINT, "3"],
        fetch=fetch,
        sleep=lambda _seconds: None,
    )
    captured = capsys.readouterr()

    assert code == 0
    assert captured.err == ""
    assert captured.out.count("\n") == 1
    payload = json.loads(captured.out)
    assert payload["probe"] == "rate_limit"
    assert payload["status"] == sidecar.OBSERVED
    assert payload["count"] == 3
    assert payload["statuses"] == [200, 200, 200]
    assert len(fetch.calls) == 3


def test_main_prints_a_rate_limit_transport_failure_as_unverified_json(capsys):
    fetch = FakeFetch(
        sidecar.TransportError(sidecar.REQUEST_TIMEOUT, "timed out")
    )

    code = sidecar.main(
        ["rate_limit", BASE, ENDPOINT, "2"],
        fetch=fetch,
        sleep=lambda _seconds: None,
    )
    captured = capsys.readouterr()

    assert code == 0
    payload = json.loads(captured.out)
    assert payload["status"] == sidecar.UNVERIFIED
    assert "timed out" in payload["evidence"]
    assert "Traceback" not in captured.err


# --- configured IDOR (sidecar mode) ---------------------------------------

IDOR_OBJECT_A = "/api/orders/1"
IDOR_OBJECT_B = "/api/orders/2"
IDOR_SECRET_A = "sidecar-alice-session"
IDOR_SECRET_B = "sidecar-bob-session"
IDOR_TOKEN_A = "sidecar-alice-token"
IDOR_API_KEY_B = "sidecar-bob-api-key"
IDOR_A = {
    "Cookie": "sid=" + IDOR_SECRET_A,
    "Authorization": "Bearer " + IDOR_TOKEN_A,
}
IDOR_B = {
    "Cookie": "sid=" + IDOR_SECRET_B,
    "X-Api-Key": IDOR_API_KEY_B,
}


def _idor_response(status=200, body='{"ok": true}', headers=None, path=IDOR_OBJECT_A):
    return sidecar.Response(
        status,
        {"Content-Type": "application/json"} if headers is None else headers,
        body,
        BASE + path,
    )


def _probe_idor(fetch):
    return sidecar.probe_idor(
        BASE, IDOR_A, IDOR_B, IDOR_OBJECT_A, IDOR_OBJECT_B, fetch=fetch
    )


def test_sidecar_idor_passing_controls_and_cross_is_exposed():
    fetch = FakeFetch(
        _idor_response(200, '{"id": 1}'),
        _idor_response(200, '{"id": 2}', path=IDOR_OBJECT_B),
        _idor_response(200, '{"id": 2, "owner": "b"}', path=IDOR_OBJECT_B),
    )

    result = _probe_idor(fetch)

    assert result["probe"] == "idor"
    assert result["verdict"] == sidecar.EXPOSED
    assert result["cause"] is None
    assert "control A" in result["evidence"]
    assert "control B" in result["evidence"]
    assert IDOR_OBJECT_A in result["evidence"]
    assert IDOR_OBJECT_B in result["evidence"]
    assert fetch.calls == [
        ("GET", BASE + IDOR_OBJECT_A, IDOR_A),
        ("GET", BASE + IDOR_OBJECT_B, IDOR_B),
        ("GET", BASE + IDOR_OBJECT_B, IDOR_A),
    ]
    assert ProbeResult(**result).verdict == sidecar.EXPOSED


def test_sidecar_idor_cross_rejected_is_not_reproduced():
    fetch = FakeFetch(
        _idor_response(200),
        _idor_response(200, path=IDOR_OBJECT_B),
        _idor_response(403, '{"error": "forbidden"}', path=IDOR_OBJECT_B),
    )

    result = _probe_idor(fetch)

    assert result["verdict"] == sidecar.NOT_REPRODUCED
    assert result["cause"] is None
    assert result["response"]["status"] == 403
    assert IDOR_OBJECT_B in result["evidence"]


@pytest.mark.parametrize(
    "response_a,response_b,failing",
    [
        (_idor_response(403, "denied"), _idor_response(200, path=IDOR_OBJECT_B), IDOR_OBJECT_A),
        (_idor_response(200), _idor_response(403, "denied", path=IDOR_OBJECT_B), IDOR_OBJECT_B),
        (_idor_response(200, "<html>login</html>", {"Content-Type": "text/html"}), _idor_response(200, path=IDOR_OBJECT_B), IDOR_OBJECT_A),
        (_idor_response(500, "boom"), _idor_response(200, path=IDOR_OBJECT_B), IDOR_OBJECT_A),
    ],
)
def test_sidecar_idor_a_failed_control_is_unverified_without_the_cross(
    response_a, response_b, failing
):
    fetch = FakeFetch(response_a, response_b)

    result = _probe_idor(fetch)

    assert result["verdict"] == sidecar.UNVERIFIED
    assert result["cause"] == sidecar.IDOR_CONTROL_FAILED
    assert len(fetch.calls) == 2
    assert failing in result["evidence"]


def test_sidecar_idor_control_transport_failure_is_unverified():
    fetch = FakeFetch(
        sidecar.TransportError(sidecar.TARGET_UNREACHABLE, "connection refused"),
        _idor_response(200, path=IDOR_OBJECT_B),
    )

    result = _probe_idor(fetch)

    assert result["verdict"] == sidecar.UNVERIFIED
    assert result["cause"] == sidecar.IDOR_CONTROL_FAILED
    assert result["response"] is None
    assert len(fetch.calls) == 2


def test_sidecar_idor_cross_transport_failure_is_unverified():
    fetch = FakeFetch(
        _idor_response(200),
        _idor_response(200, path=IDOR_OBJECT_B),
        sidecar.TransportError(sidecar.REQUEST_TIMEOUT, "request timed out"),
    )

    result = _probe_idor(fetch)

    assert result["verdict"] == sidecar.UNVERIFIED
    assert result["cause"] == sidecar.REQUEST_TIMEOUT
    assert result["response"] is None


def test_sidecar_idor_an_inconclusive_cross_is_unverified():
    fetch = FakeFetch(
        _idor_response(200),
        _idor_response(200, path=IDOR_OBJECT_B),
        _idor_response(500, "boom", path=IDOR_OBJECT_B),
    )

    result = _probe_idor(fetch)

    assert result["verdict"] == sidecar.UNVERIFIED
    assert result["verdict"] != sidecar.EXPOSED


@pytest.mark.parametrize("path", ["http://evil.invalid/1", "api/orders/1", "", "/x y"])
def test_sidecar_idor_refuses_a_non_path_object_before_any_fetch(path):
    fetch = FakeFetch()

    result = sidecar.probe_idor(BASE, IDOR_A, IDOR_B, path, IDOR_OBJECT_B, fetch=fetch)

    assert result["verdict"] == sidecar.UNVERIFIED
    assert result["cause"] == sidecar.INVALID_ENDPOINT
    assert result["response"] is None
    assert fetch.calls == []
    assert IDOR_SECRET_A not in json.dumps(result)


def test_sidecar_idor_redacts_stored_credentials_but_not_the_request():
    response_headers = {
        "Content-Type": "application/json",
        "Set-Cookie": "sid=" + IDOR_SECRET_B,
        "Authorization": "Bearer " + IDOR_TOKEN_A,
    }
    fetch = FakeFetch(
        _idor_response(200, '{"id": 1}', response_headers),
        _idor_response(200, '{"id": 2}', response_headers, IDOR_OBJECT_B),
        _idor_response(200, '{"id": 2}', response_headers, IDOR_OBJECT_B),
    )

    result = _probe_idor(fetch)

    stored = json.dumps(result)
    for secret in (IDOR_SECRET_A, IDOR_SECRET_B, IDOR_TOKEN_A, IDOR_API_KEY_B):
        assert secret not in stored

    assert result["request"]["headers"] == {
        "cookie": "[redacted]",
        "authorization": "[redacted]",
    }
    assert set(result["response"]["headers"]) == {
        "content-type",
        "set-cookie",
        "authorization",
    }
    assert result["response"]["headers"]["set-cookie"] == "[redacted]"
    assert result["response"]["headers"]["authorization"] == "[redacted]"
    assert result["response"]["headers"]["content-type"] == "application/json"

    # The fake fetch saw the real values, not the redacted ones.
    assert fetch.calls[0][2] == IDOR_A
    assert fetch.calls[1][2] == IDOR_B
    assert fetch.calls[2][2] == IDOR_A


@pytest.mark.parametrize(
    "data",
    [
        None,
        "{not json",
        "[]",
        '{"identity_a": {"headers": {"Cookie": "a=1"}}}',
        '{"identity_a": {"headers": {"Cookie": "a=1"}}, '
        '"identity_b": {"headers": []}, "object_a": "/a", "object_b": "/b"}',
        '{"identity_a": {"headers": {"Cookie": 1}}, '
        '"identity_b": {"headers": {"Cookie": "b=2"}}, '
        '"object_a": "/a", "object_b": "/b"}',
        '{"identity_a": {"headers": {"Cookie": "a=1"}}, '
        '"identity_b": {"headers": {"Cookie": "b=2"}}}',
    ],
)
def test_main_reports_a_bad_idor_config_without_a_traceback(tmp_path, capsys, data):
    path = tmp_path / "idor.json"
    if data is not None:
        path.write_text(data, encoding="utf-8")
        os.chmod(str(path), 0o600)

    code = sidecar.main(["idor", BASE, str(path)], fetch=FakeFetch())
    captured = capsys.readouterr()

    assert code == 2
    assert captured.out == ""
    assert "usage" in captured.err.lower()
    assert "Traceback" not in captured.err
    assert str(path) not in captured.err
    assert IDOR_SECRET_A not in captured.err


@pytest.mark.parametrize(
    "argv",
    [["idor", BASE], ["idor", BASE, "one.json", "extra"]],
)
def test_main_rejects_idor_with_the_wrong_argument_count(argv, capsys):
    code = sidecar.main(argv, fetch=FakeFetch())
    captured = capsys.readouterr()

    assert code == 2
    assert captured.out == ""
    assert "usage" in captured.err.lower()


# --- response header observation (sidecar mode) ---------------------------

HEADERS_BASE = "http://app:3000"
HTTPS_BASE = "https://app:3000"


def _headers_response(headers=None, body="ok", status=200, base=HEADERS_BASE):
    return sidecar.Response(status, headers or {}, body, base + "/")


def test_headers_observation_lists_missing_and_present_in_recommended_order():
    fetch = FakeFetch(
        _headers_response(
            {
                "X-Frame-Options": "DENY",
                "X-Content-Type-Options": "nosniff",
            }
        )
    )

    result = sidecar.probe_headers(HEADERS_BASE, fetch=fetch)

    assert result["probe"] == "headers"
    assert result["status"] == sidecar.OBSERVED
    assert result["present"] == [
        "x-content-type-options",
        "x-frame-options",
    ]
    assert result["missing"] == [
        name
        for name in sidecar.RECOMMENDED_HEADERS
        if name not in ("x-content-type-options", "x-frame-options")
    ]
    assert "hardening observation" in result["evidence"]
    assert "secure" not in result["evidence"].lower()
    assert fetch.calls == [
        ("GET", HEADERS_BASE + "/", {"User-Agent": sidecar.USER_AGENT})
    ]
    assert len(fetch.calls) == 1
    assert result["request"] == {
        "method": "GET",
        "url": HEADERS_BASE + "/",
        "headers": {"user-agent": sidecar.USER_AGENT},
    }
    assert set(result) == {
        "probe",
        "status",
        "evidence",
        "request",
        "response",
        "missing",
        "present",
    }
    assert "verdict" not in result
    assert "proof" not in result


def test_headers_observation_requires_hsts_only_over_https():
    http_fetch = FakeFetch(
        _headers_response({"Strict-Transport-Security": "max-age=1"})
    )
    https_fetch = FakeFetch(
        _headers_response(
            {"Strict-Transport-Security": "max-age=1"}, base=HTTPS_BASE
        )
    )

    http_result = sidecar.probe_headers(HEADERS_BASE, fetch=http_fetch)
    https_result = sidecar.probe_headers(HTTPS_BASE, fetch=https_fetch)

    assert sidecar.HSTS_HEADER not in http_result["missing"]
    assert sidecar.HSTS_HEADER not in http_result["present"]
    assert len(http_result["missing"]) == len(sidecar.RECOMMENDED_HEADERS)
    assert "strict-transport-security" not in sidecar.RECOMMENDED_HEADERS
    assert https_result["present"] == ["strict-transport-security"]
    assert https_result["missing"] == list(sidecar.RECOMMENDED_HEADERS)
    assert https_fetch.calls[0][1] == HTTPS_BASE + "/"


def test_headers_observation_lowercases_response_headers_and_caps_the_body():
    fetch = FakeFetch(
        _headers_response(
            {"X-Test": "1"}, body="x" * (sidecar.BODY_LIMIT * 2)
        )
    )

    result = sidecar.probe_headers(HEADERS_BASE, fetch=fetch)

    assert result["response"]["headers"] == {"x-test": "1"}
    assert len(result["response"]["body"]) == sidecar.BODY_LIMIT
    assert sidecar.BODY_LIMIT == 4096


def test_headers_observation_normalizes_a_trailing_slash():
    fetch = FakeFetch(_headers_response())

    sidecar.probe_headers(HEADERS_BASE + "///", fetch=fetch)

    assert fetch.calls[0][1] == HEADERS_BASE + "/"


def test_headers_transport_failure_is_unverified():
    fetch = FakeFetch(
        sidecar.TransportError(sidecar.TARGET_UNREACHABLE, "connection refused")
    )

    result = sidecar.probe_headers(HEADERS_BASE, fetch=fetch)

    assert result["status"] == sidecar.UNVERIFIED
    assert result["response"] is None
    assert result["missing"] == []
    assert result["present"] == []
    assert sidecar.TARGET_UNREACHABLE in result["evidence"]
    assert "Traceback" not in result["evidence"]
    assert "verdict" not in result


def test_the_headers_observation_is_not_a_probe_result():
    fetch = FakeFetch(_headers_response())

    result = sidecar.probe_headers(HEADERS_BASE, fetch=fetch)

    with pytest.raises(TypeError):
        ProbeResult(**result)


def test_main_accepts_headers(capsys):
    fetch = FakeFetch(_headers_response({"X-Frame-Options": "DENY"}))

    code = sidecar.main(["headers", HEADERS_BASE], fetch=fetch)
    captured = capsys.readouterr()

    assert code == 0
    assert captured.err == ""
    assert captured.out.count("\n") == 1
    payload = json.loads(captured.out)
    assert payload["probe"] == "headers"
    assert payload["status"] == sidecar.OBSERVED
    assert payload["present"] == ["x-frame-options"]
    assert fetch.calls[0][1] == HEADERS_BASE + "/"


@pytest.mark.parametrize(
    "argv",
    [["headers"], ["headers", HEADERS_BASE, "extra"]],
)
def test_main_rejects_headers_with_the_wrong_argument_count(argv, capsys):
    code = sidecar.main(argv, fetch=FakeFetch())
    captured = capsys.readouterr()

    assert code == 2
    assert captured.out == ""
    assert "usage" in captured.err.lower()


def test_main_reads_the_idor_config_and_prints_redacted_json(capsys, tmp_path):
    path = tmp_path / "idor.json"
    path.write_text(
        json.dumps(
            {
                "identity_a": {"headers": IDOR_A},
                "identity_b": {"headers": IDOR_B},
                "object_a": IDOR_OBJECT_A,
                "object_b": IDOR_OBJECT_B,
            }
        ),
        encoding="utf-8",
    )
    os.chmod(str(path), 0o600)
    fetch = FakeFetch(
        _idor_response(200, '{"id": 1}'),
        _idor_response(200, '{"id": 2}', path=IDOR_OBJECT_B),
        _idor_response(200, '{"id": 2}', path=IDOR_OBJECT_B),
    )

    code = sidecar.main(["idor", BASE, str(path)], fetch=fetch)
    captured = capsys.readouterr()

    assert code == 0
    assert captured.err == ""
    assert captured.out.count("\n") == 1
    payload = json.loads(captured.out)
    assert payload["probe"] == "idor"
    assert payload["verdict"] == sidecar.EXPOSED
    assert captured.out.count(IDOR_SECRET_A) == 0
    assert IDOR_SECRET_B not in captured.out
    assert str(path) not in captured.out
    assert fetch.calls == [
        ("GET", BASE + IDOR_OBJECT_A, IDOR_A),
        ("GET", BASE + IDOR_OBJECT_B, IDOR_B),
        ("GET", BASE + IDOR_OBJECT_B, IDOR_A),
    ]
