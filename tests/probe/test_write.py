"""Level 2 write config tests (AT1-AT6).

Nothing here starts a container or opens a socket.
"""

import json
import os

import pytest

from pry.probe.results import ProbeError
from pry.probe.write import (
    WRITE_BODY_LIMIT,
    WRITE_CONFIG_INVALID,
    WriteConfig,
    load_write_config,
    validate_write_config,
)

BODY = '{"name": "{{marker}}", "note": "pry test data"}'


def _payload(**overrides):
    data = {
        "method": "POST",
        "endpoint": "/api/write",
        "body": BODY,
        "verify_endpoint": "/api/write",
        "verify_contains": "{{marker}}",
        "content_type": "application/json",
    }
    data.update(overrides)
    return data


def _write_file(tmp_path, data, mode=0o600):
    path = tmp_path / "write.json"
    path.write_text(
        data if isinstance(data, str) else json.dumps(data),
        encoding="utf-8",
    )
    os.chmod(str(path), mode)
    return path


def _invalid(data):
    with pytest.raises(ProbeError) as exc:
        validate_write_config(data)
    assert exc.value.cause == WRITE_CONFIG_INVALID
    assert exc.value.message
    return exc.value.message


def test_load_write_config_accepts_a_0600_object(tmp_path):
    path = _write_file(tmp_path, _payload())

    config = load_write_config(path)

    assert config == WriteConfig(
        method="POST",
        endpoint="/api/write",
        body=BODY,
        verify_endpoint="/api/write",
        verify_contains="{{marker}}",
        content_type="application/json",
    )


@pytest.mark.parametrize("method", ["POST", "PUT", "PATCH"])
def test_load_write_config_accepts_every_write_method(tmp_path, method):
    path = _write_file(tmp_path, _payload(method=method))

    assert load_write_config(path).method == method


def test_verify_contains_and_content_type_default(tmp_path):
    data = _payload()
    del data["verify_contains"]
    del data["content_type"]
    path = _write_file(tmp_path, data)

    config = load_write_config(path)

    assert config.verify_contains == "{{marker}}"
    assert config.content_type == "application/json"
    assert WRITE_BODY_LIMIT == 4096


@pytest.mark.parametrize("mode", [0o644, 0o640, 0o604])
def test_load_write_config_refuses_group_or_other_access(tmp_path, mode):
    path = _write_file(tmp_path, _payload(), mode=mode)

    with pytest.raises(ProbeError) as exc:
        load_write_config(path)

    assert exc.value.cause == WRITE_CONFIG_INVALID
    assert "chmod 600" in exc.value.message
    assert str(path) not in exc.value.message


def test_load_write_config_refuses_a_missing_file(tmp_path):
    path = tmp_path / "missing.json"

    with pytest.raises(ProbeError) as exc:
        load_write_config(path)

    assert exc.value.cause == WRITE_CONFIG_INVALID
    assert "missing or unreadable" in exc.value.message
    assert str(path) not in exc.value.message


def test_load_write_config_refuses_a_directory(tmp_path):
    with pytest.raises(ProbeError) as exc:
        load_write_config(tmp_path)

    assert exc.value.cause == WRITE_CONFIG_INVALID
    assert "regular file" in exc.value.message


@pytest.mark.parametrize("text", ["{not json", "[]", '"text"', "null"])
def test_load_write_config_refuses_a_non_object(tmp_path, text):
    path = _write_file(tmp_path, text)

    with pytest.raises(ProbeError) as exc:
        load_write_config(path)

    assert exc.value.cause == WRITE_CONFIG_INVALID
    assert str(path) not in exc.value.message


@pytest.mark.parametrize("method", ["DELETE", "GET", "", None, 1])
def test_validate_refuses_an_unsupported_method(method):
    message = _invalid(_payload(method=method))

    assert "method" in message


@pytest.mark.parametrize(
    "endpoint",
    [
        "http://evil.invalid/api",
        "https://evil.invalid/api",
        "//evil.invalid/api",
        "api/write",
        "",
        "/api write",
        "/api\twrite",
        "/api\nwrite",
        "/api\x00write",
        "/api/write?x=1",
        "/api/write#frag",
        "/" + "a" * 2048,
        None,
    ],
)
def test_validate_refuses_a_non_path_endpoint(endpoint):
    message = _invalid(_payload(endpoint=endpoint))

    assert "endpoint" in message


@pytest.mark.parametrize(
    "verify_endpoint",
    [
        "http://evil.invalid/api",
        "//evil.invalid/api",
        "api/write",
        "/api/write?x=1",
        "/api/write#frag",
        "/api write",
        None,
    ],
)
def test_validate_refuses_a_non_path_verification_endpoint(verify_endpoint):
    message = _invalid(_payload(verify_endpoint=verify_endpoint))

    assert "verify_endpoint" in message


@pytest.mark.parametrize("body", [None, "", 1, [], "no marker here"])
def test_validate_refuses_a_body_without_the_marker(body):
    message = _invalid(_payload(body=body))

    assert "body" in message


def test_validate_refuses_an_oversized_body():
    body = '{"name": "{{marker}}", "note": "' + "x" * WRITE_BODY_LIMIT + '"}'

    message = _invalid(_payload(body=body))

    assert "body" in message
    assert str(WRITE_BODY_LIMIT) in message


@pytest.mark.parametrize("verify_contains", [None, "", "stored", 1, ["{{marker}}"]])
def test_validate_refuses_a_verification_without_the_marker(verify_contains):
    message = _invalid(_payload(verify_contains=verify_contains))

    assert "verify_contains" in message


@pytest.mark.parametrize(
    "content_type",
    ["", 1, "application/json\r\nX-Injected: 1", "a" * 129],
)
def test_validate_refuses_an_invalid_content_type(content_type):
    message = _invalid(_payload(content_type=content_type))

    assert "content_type" in message


def test_validate_does_not_echo_the_body_value():
    message = _invalid(_payload(body="super-secret-value without a marker"))

    assert "super-secret-value" not in message


def test_validate_keeps_only_the_declared_fields():
    config = validate_write_config(_payload(extra="ignored"))

    assert config == WriteConfig(
        method="POST",
        endpoint="/api/write",
        body=BODY,
        verify_endpoint="/api/write",
        verify_contains="{{marker}}",
        content_type="application/json",
    )
