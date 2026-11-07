"""Configured IDOR probe tests (AT1-AT6).

Every HTTP call is faked: nothing in this file opens a socket.
"""

import json
import os

import pytest

from pry.probe.idor import IdorConfig, load_idor_config, probe_idor
from pry.probe.results import (
    EXPOSED,
    NOT_REPRODUCED,
    UNVERIFIED,
    ProbeError,
    ProbeResult,
)
from pry.probe.sidecar import Response, TransportError

BASE = "https://app.example.com"
SECRET_A = "alice-session-secret"
SECRET_B = "bob-session-secret"
TOKEN_A = "alice-token-secret"
TOKEN_B = "bob-token-secret"
API_KEY_A = "alice-api-key-secret"
API_KEY_B = "server-api-key-secret"
REDACTED = "[redacted]"


def _config(**overrides):
    data = {
        "headers_a": {
            "Cookie": "sid=" + SECRET_A,
            "Authorization": "Bearer " + TOKEN_A,
            "X-Api-Key": API_KEY_A,
        },
        "headers_b": {
            "Cookie": "sid=" + SECRET_B,
            "Proxy-Authorization": "Basic " + TOKEN_B,
        },
        "object_a": "/api/orders/1",
        "object_b": "/api/orders/2",
    }
    data.update(overrides)
    return IdorConfig(**data)


def _payload(headers_a=None, headers_b=None, object_a="/a", object_b="/b"):
    return {
        "identity_a": {
            "headers": {"Cookie": "a=1"} if headers_a is None else headers_a
        },
        "identity_b": {
            "headers": {"Cookie": "b=2"} if headers_b is None else headers_b
        },
        "object_a": object_a,
        "object_b": object_b,
    }


def _write_config(tmp_path, data=None, mode=0o600, name="idor.json"):
    path = tmp_path / name
    payload = _payload() if data is None else data
    path.write_text(json.dumps(payload), encoding="utf-8")
    os.chmod(str(path), mode)
    return path


def _response(status=200, body='{"ok": true}', headers=None, path="/"):
    return Response(
        status,
        {"Content-Type": "application/json"} if headers is None else headers,
        body,
        BASE + path,
    )


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


def _assert_config_error(path):
    with pytest.raises(ProbeError) as exc:
        load_idor_config(path)
    assert exc.value.cause == "IDOR_CONFIG_INVALID"
    assert str(path) not in str(exc.value)
    assert path.name not in str(exc.value)
    return exc.value


def test_load_idor_config_accepts_a_0600_file(tmp_path):
    path = _write_config(
        tmp_path,
        _payload(
            headers_a={"Cookie": "sid=" + SECRET_A},
            headers_b={"Cookie": "sid=" + SECRET_B},
        ),
    )

    config = load_idor_config(path)

    assert config == IdorConfig(
        headers_a={"Cookie": "sid=" + SECRET_A},
        headers_b={"Cookie": "sid=" + SECRET_B},
        object_a="/a",
        object_b="/b",
    )


@pytest.mark.parametrize("mode", [0o644, 0o640, 0o604, 0o666])
def test_load_idor_config_refuses_group_or_other_permissions(tmp_path, mode):
    path = _write_config(tmp_path, mode=mode)

    _assert_config_error(path)


def test_load_idor_config_refuses_a_missing_file(tmp_path):
    _assert_config_error(tmp_path / "missing.json")


def test_load_idor_config_refuses_malformed_json(tmp_path):
    path = tmp_path / "idor.json"
    path.write_text("{not json", encoding="utf-8")
    os.chmod(str(path), 0o600)

    _assert_config_error(path)


@pytest.mark.parametrize(
    "data",
    [
        [],
        {},
        {"identity_a": {"headers": {"Cookie": "a"}}},
        {"identity_a": {"headers": {}}, "identity_b": {"headers": {"Cookie": "b"}}},
        {"identity_a": {"headers": []}, "identity_b": {"headers": {"Cookie": "b"}}},
        {"identity_a": "a", "identity_b": {"headers": {"Cookie": "b"}}},
        {"identity_a": {"headers": {"Cookie": "a"}}, "identity_b": {"headers": {}}},
    ],
)
def test_load_idor_config_refuses_invalid_identity_shapes(tmp_path, data):
    _assert_config_error(_write_config(tmp_path, data))


@pytest.mark.parametrize(
    "object_a",
    [
        "http://evil.invalid/orders/1",
        "//evil.invalid/orders/1",
        "api/orders/1",
        "/api orders",
        "/api/\x01",
        "",
    ],
)
def test_load_idor_config_refuses_non_path_only_objects(tmp_path, object_a):
    _assert_config_error(
        _write_config(tmp_path, _payload(object_a=object_a))
    )


@pytest.mark.parametrize(
    "name",
    ["Host", "host", "Content-Length", "Transfer-Encoding", "transfer-encoding"],
)
def test_load_idor_config_refuses_forbidden_headers(tmp_path, name):
    _assert_config_error(
        _write_config(tmp_path, _payload(headers_a={name: "value"}))
    )


@pytest.mark.parametrize(
    "name", ["Bad Name", "Bad:Name", "Bad\nName", "", "Caf\u00e9"]
)
def test_load_idor_config_refuses_invalid_header_names(tmp_path, name):
    _assert_config_error(
        _write_config(tmp_path, _payload(headers_a={name: "value"}))
    )


@pytest.mark.parametrize(
    "value",
    [
        "",
        "line\ninjection",
        "carriage\rreturn",
        "null\x00byte",
        "unit\x1fseparator",
        "delete\x7fchar",
        "x" * 4097,
    ],
)
def test_load_idor_config_refuses_invalid_header_values(tmp_path, value):
    _assert_config_error(
        _write_config(tmp_path, _payload(headers_a={"Cookie": value}))
    )


def test_load_idor_config_refuses_a_non_string_header_value(tmp_path):
    _assert_config_error(
        _write_config(tmp_path, _payload(headers_a={"Cookie": 123}))
    )


def test_load_idor_config_accepts_a_4096_character_value(tmp_path):
    value = "x" * 4096
    path = _write_config(tmp_path, _payload(headers_a={"Cookie": value}))

    assert load_idor_config(path).headers_a["Cookie"] == value


def test_probe_idor_with_passing_controls_and_cross_is_exposed():
    config = _config()
    fetch = FakeFetch(
        _response(200, '{"id": 1}', path=config.object_a),
        _response(200, '{"id": 2}', path=config.object_b),
        _response(200, '{"id": 2, "owner": "alice"}', path=config.object_b),
    )

    result = probe_idor(BASE, config, fetch=fetch)

    assert result["probe"] == "idor"
    assert result["verdict"] == EXPOSED
    assert result["cause"] is None
    evidence = result["evidence"]
    assert config.object_a in evidence
    assert config.object_b in evidence
    assert "control A" in evidence
    assert "control B" in evidence
    assert "status 200" in evidence
    assert fetch.calls == [
        ("GET", BASE + config.object_a, config.headers_a),
        ("GET", BASE + config.object_b, config.headers_b),
        ("GET", BASE + config.object_b, config.headers_a),
    ]
    assert ProbeResult(**result).verdict == EXPOSED


@pytest.mark.parametrize("status", [401, 403, 404])
def test_probe_idor_cross_rejected_is_not_reproduced(status):
    config = _config()
    fetch = FakeFetch(
        _response(200),
        _response(200),
        _response(status, "denied"),
    )

    result = probe_idor(BASE, config, fetch=fetch)

    assert result["verdict"] == NOT_REPRODUCED
    assert result["cause"] is None
    assert result["response"]["status"] == status
    assert config.object_b in result["evidence"]


@pytest.mark.parametrize(
    "response_a,response_b,failing",
    [
        (_response(401, "denied"), _response(200), "/api/orders/1"),
        (_response(200), _response(403, "denied"), "/api/orders/2"),
        (
            _response(200, "<html>login</html>", {"Content-Type": "text/html"}),
            _response(200),
            "/api/orders/1",
        ),
        (_response(200, ""), _response(200), "/api/orders/1"),
        (_response(200), _response(200, ""), "/api/orders/2"),
        (_response(302, ""), _response(200), "/api/orders/1"),
        (_response(500, "boom"), _response(200), "/api/orders/1"),
    ],
)
def test_probe_idor_a_failed_control_is_unverified_without_the_cross(
    response_a, response_b, failing
):
    config = _config()
    fetch = FakeFetch(response_a, response_b)

    result = probe_idor(BASE, config, fetch=fetch)

    assert result["verdict"] == UNVERIFIED
    assert result["cause"] == "IDOR_CONTROL_FAILED"
    assert len(fetch.calls) == 2
    assert failing in result["evidence"]
    assert config.object_a in result["evidence"]
    assert config.object_b in result["evidence"]
    assert ProbeResult(**result).verdict == UNVERIFIED


def test_probe_idor_control_transport_failure_is_unverified():
    config = _config()
    fetch = FakeFetch(
        TransportError("TARGET_UNREACHABLE", "boom"), _response(200)
    )

    result = probe_idor(BASE, config, fetch=fetch)

    assert result["verdict"] == UNVERIFIED
    assert result["cause"] == "IDOR_CONTROL_FAILED"
    assert result["response"] is None
    assert len(fetch.calls) == 2
    assert "control A" in result["evidence"]
    assert "control B" in result["evidence"]


def test_probe_idor_cross_transport_failure_is_unverified():
    config = _config()
    fetch = FakeFetch(
        _response(200),
        _response(200),
        TransportError("REQUEST_TIMEOUT", "request timed out"),
    )

    result = probe_idor(BASE, config, fetch=fetch)

    assert result["verdict"] == UNVERIFIED
    assert result["cause"] == "REQUEST_TIMEOUT"
    assert result["response"] is None
    assert config.object_a in result["evidence"]
    assert config.object_b in result["evidence"]


@pytest.mark.parametrize(
    "response",
    [
        _response(500, "boom"),
        _response(302, ""),
        _response(200, "<html>login</html>", {"Content-Type": "text/html"}),
        _response(200, ""),
    ],
)
def test_probe_idor_an_inconclusive_cross_is_unverified(response):
    config = _config()
    fetch = FakeFetch(_response(200), _response(200), response)

    result = probe_idor(BASE, config, fetch=fetch)

    assert result["verdict"] == UNVERIFIED
    assert result["verdict"] != EXPOSED


def test_probe_idor_redacts_stored_credentials_but_not_the_request():
    config = _config()
    response_headers = {
        "Content-Type": "application/json",
        "Set-Cookie": "sid=" + SECRET_B,
        "X-Api-Key": API_KEY_B,
        "X-Trace": "visible-value",
    }
    fetch = FakeFetch(
        _response(200, '{"id": 1}', response_headers),
        _response(200, '{"id": 2}', response_headers),
        _response(200, '{"id": 2}', response_headers),
    )

    result = probe_idor(BASE, config, fetch=fetch)

    stored = json.dumps(result)
    for secret in (
        SECRET_A,
        SECRET_B,
        TOKEN_A,
        TOKEN_B,
        API_KEY_A,
        API_KEY_B,
    ):
        assert secret not in stored

    request_headers = result["request"]["headers"]
    assert request_headers["cookie"] == REDACTED
    assert request_headers["authorization"] == REDACTED
    assert request_headers["x-api-key"] == REDACTED
    response_stored = result["response"]["headers"]
    assert response_stored["set-cookie"] == REDACTED
    assert response_stored["x-api-key"] == REDACTED
    assert response_stored["x-trace"] == "visible-value"

    # The fake fetch must have seen the real values, not the redacted ones.
    assert fetch.calls[0][2] == config.headers_a
    assert fetch.calls[1][2] == config.headers_b
    assert fetch.calls[2][2] == config.headers_a


def test_probe_idor_redacts_proxy_authorization_on_a_control_failure():
    config = _config()
    fetch = FakeFetch(
        _response(200),
        _response(403, "denied", {"Set-Cookie": "sid=" + SECRET_B}),
    )

    result = probe_idor(BASE, config, fetch=fetch)

    stored = json.dumps(result)
    assert TOKEN_B not in stored
    assert SECRET_B not in stored
    assert result["request"]["headers"]["proxy-authorization"] == REDACTED
    assert result["response"]["headers"]["set-cookie"] == REDACTED


def test_probe_idor_result_never_contains_the_config_path(tmp_path):
    path = _write_config(
        tmp_path,
        _payload(
            headers_a={"Cookie": "sid=" + SECRET_A},
            headers_b={"Cookie": "sid=" + SECRET_B},
        ),
    )
    config = load_idor_config(path)
    fetch = FakeFetch(_response(200), _response(200), _response(200))

    result = probe_idor(BASE, config, fetch=fetch)

    stored = json.dumps(result)
    assert str(path) not in stored
    assert path.name not in stored
    assert str(path.parent) not in stored
