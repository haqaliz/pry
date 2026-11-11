"""Provider database config and marker-gated read tests (AT1-AT7).

Every probe takes an injected ``fetch``; nothing here opens a socket.
"""

import json
import os

import pytest

from pry.probe.database_rules import (
    DATABASE_CONFIG_INVALID,
    DATABASE_INVALID,
    DATABASE_MARKER_MISMATCH,
    DATABASE_MARKER_UNVERIFIED,
    DatabaseConfig,
    DatabaseError,
    load_database_config,
    probe_database_rules,
)
from pry.probe.results import (
    BODY_LIMIT,
    EXPOSED,
    NOT_REPRODUCED,
    UNVERIFIED,
    ProbeError,
    ProbeResult,
)
from pry.probe.sidecar import TARGET_UNREACHABLE, Response, TransportError

FIREBASE_URL = "https://demo.firebaseio.com"
SUPABASE_URL = "https://project.supabase.co"
MARKER = "pry-test-marker-abc123"
ANON_KEY = "anon-key-1234567890"
MARKER_PATH = "/pry_ownership.json"
FIREBASE_DATA_PATH = "/users.json"
SUPABASE_MARKER_PATH = "/rest/v1/pry_ownership?select=marker"
SUPABASE_DATA_PATH = "/rest/v1/users?select=*"


def _firebase_payload(**overrides):
    data = {
        "provider": "firebase-rtdb",
        "url": FIREBASE_URL + "/",
        "marker_path": "/pry_ownership",
        "marker": MARKER,
        "read_path": "/users",
    }
    data.update(overrides)
    return data


def _supabase_payload(**overrides):
    data = {
        "provider": "supabase",
        "url": SUPABASE_URL + "/",
        "marker_path": SUPABASE_MARKER_PATH,
        "marker": MARKER,
        "read_path": SUPABASE_DATA_PATH,
        "anon_key": ANON_KEY,
    }
    data.update(overrides)
    return data


def _write_config(tmp_path, data, mode=0o600, name="db.json"):
    path = tmp_path / name
    path.write_text(
        data if isinstance(data, str) else json.dumps(data),
        encoding="utf-8",
    )
    os.chmod(str(path), mode)
    return path


def _invalid_config(tmp_path, data, mode=0o600):
    path = _write_config(tmp_path, data, mode)
    with pytest.raises(ProbeError) as exc:
        load_database_config(path)
    assert exc.value.cause == DATABASE_CONFIG_INVALID
    assert exc.value.message
    assert str(path) not in exc.value.message
    return exc.value.message


def _firebase_config():
    return DatabaseConfig(
        provider="firebase-rtdb",
        url=FIREBASE_URL,
        marker_path=MARKER_PATH,
        marker=MARKER,
        read_path=FIREBASE_DATA_PATH,
    )


def _supabase_config():
    return DatabaseConfig(
        provider="supabase",
        url=SUPABASE_URL,
        marker_path=SUPABASE_MARKER_PATH,
        marker=MARKER,
        read_path=SUPABASE_DATA_PATH,
        anon_key=ANON_KEY,
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


def _response(
    base_url, path, body="", status=200, final_url=None, headers=None
):
    return Response(
        status,
        dict(headers or {"Content-Type": "application/json"}),
        body,
        base_url + path if final_url is None else final_url,
    )


def _firebase_marker(body=None, **kwargs):
    return _response(
        FIREBASE_URL,
        MARKER_PATH,
        json.dumps(MARKER) if body is None else body,
        **kwargs
    )


def _firebase_data(body, status=200, final_url=None, headers=None):
    return _response(
        FIREBASE_URL,
        FIREBASE_DATA_PATH,
        body,
        status=status,
        final_url=final_url,
        headers=headers,
    )


def _supabase_marker(body=None, **kwargs):
    return _response(
        SUPABASE_URL,
        SUPABASE_MARKER_PATH,
        json.dumps([{"marker": MARKER}]) if body is None else body,
        **kwargs
    )


def _supabase_data(body, status=200, final_url=None):
    return _response(
        SUPABASE_URL,
        SUPABASE_DATA_PATH,
        body,
        status=status,
        final_url=final_url,
    )


# Config loading and validation


def test_load_firebase_config_normalizes_the_url_and_paths(tmp_path):
    path = _write_config(tmp_path, _firebase_payload())

    config = load_database_config(path)

    assert config == DatabaseConfig(
        provider="firebase-rtdb",
        url=FIREBASE_URL,
        marker_path=MARKER_PATH,
        marker=MARKER,
        read_path=FIREBASE_DATA_PATH,
        anon_key=None,
    )


def test_load_supabase_config_keeps_the_query_and_anon_key(tmp_path):
    path = _write_config(tmp_path, _supabase_payload())

    config = load_database_config(path)

    assert config == DatabaseConfig(
        provider="supabase",
        url=SUPABASE_URL,
        marker_path=SUPABASE_MARKER_PATH,
        marker=MARKER,
        read_path=SUPABASE_DATA_PATH,
        anon_key=ANON_KEY,
    )


def test_load_accepts_an_owner_read_only_config(tmp_path):
    path = _write_config(tmp_path, _firebase_payload(), mode=0o400)

    assert load_database_config(path).provider == "firebase-rtdb"


@pytest.mark.parametrize("mode", [0o644, 0o640, 0o604])
def test_load_refuses_group_or_other_access(tmp_path, mode):
    message = _invalid_config(tmp_path, _firebase_payload(), mode=mode)

    assert "chmod 600" in message


def test_load_refuses_a_missing_file(tmp_path):
    path = tmp_path / "missing.json"

    with pytest.raises(ProbeError) as exc:
        load_database_config(path)

    assert exc.value.cause == DATABASE_CONFIG_INVALID
    assert "missing or unreadable" in exc.value.message
    assert str(path) not in exc.value.message


def test_load_refuses_a_directory(tmp_path):
    with pytest.raises(ProbeError) as exc:
        load_database_config(tmp_path)

    assert exc.value.cause == DATABASE_CONFIG_INVALID
    assert "regular file" in exc.value.message


@pytest.mark.parametrize("text", ["{not json", "[]", "null", '"text"'])
def test_load_refuses_invalid_json_or_a_non_object(tmp_path, text):
    _invalid_config(tmp_path, text)


@pytest.mark.parametrize("provider", ["firestore", "", None, 1, ["supabase"]])
def test_validate_refuses_an_unknown_provider(tmp_path, provider):
    message = _invalid_config(
        tmp_path, _firebase_payload(provider=provider)
    )

    assert "provider" in message


@pytest.mark.parametrize(
    "url",
    [
        "",
        None,
        "not a url",
        "ftp://example.com",
        "https://",
        "https://user:hidden-password@example.com",
        "https://user@example.com",
        "https://example.com?query=1",
        "https://example.com/#fragment",
        "https://example.com/some/path",
        "https://example.com//",
        "https://exa mple.com",
        "https://example.com:not-a-port",
    ],
)
def test_validate_refuses_an_unsafe_url(tmp_path, url):
    message = _invalid_config(tmp_path, _firebase_payload(url=url))

    assert "url" in message
    assert "hidden-password" not in message


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1:9000",
        "http://localhost:9000",
        "http://[::1]:9000",
    ],
)
def test_validate_allows_http_on_loopback(url, tmp_path):
    path = _write_config(tmp_path, _firebase_payload(url=url))

    assert load_database_config(path).url == url


def test_validate_requires_https_off_loopback(tmp_path):
    message = _invalid_config(
        tmp_path, _firebase_payload(url="http://example.com")
    )

    assert "HTTPS" in message


@pytest.mark.parametrize(
    "marker", [None, "", "pry-too-short", 1, [], "x" * 257, "pry-bad\x00marker"]
)
def test_validate_refuses_an_invalid_marker(tmp_path, marker):
    message = _invalid_config(
        tmp_path, _firebase_payload(marker=marker)
    )

    assert "marker" in message


@pytest.mark.parametrize("marker", ["abcdefghijklmnop", "x" * 256])
def test_validate_accepts_marker_boundaries_without_a_prefix(
    tmp_path, marker
):
    path = _write_config(tmp_path, _firebase_payload(marker=marker))

    assert load_database_config(path).marker == marker


@pytest.mark.parametrize(
    "value",
    [
        None,
        "",
        "users",
        "https://evil.invalid/users",
        "/users?select=*",
        "/users#fragment",
        "/users name",
        "/users\tname",
        "/users\x00name",
        "/" + "a" * 2048,
        1,
    ],
)
def test_validate_refuses_an_invalid_firebase_path(tmp_path, value):
    message = _invalid_config(
        tmp_path, _firebase_payload(marker_path=value)
    )

    assert "marker_path" in message


def test_validate_refuses_an_invalid_firebase_read_path(tmp_path):
    message = _invalid_config(tmp_path, _firebase_payload(read_path="/users?x=1"))

    assert "read_path" in message


def test_firebase_paths_get_a_json_suffix_once(tmp_path):
    path = _write_config(
        tmp_path,
        _firebase_payload(
            marker_path="/already.json", read_path="/users"
        ),
    )

    config = load_database_config(path)

    assert config.marker_path == "/already.json"
    assert config.read_path == "/users.json"


def test_supabase_query_paths_are_allowed(tmp_path):
    path = _write_config(tmp_path, _supabase_payload())

    config = load_database_config(path)

    assert config.marker_path == SUPABASE_MARKER_PATH
    assert config.read_path == SUPABASE_DATA_PATH


@pytest.mark.parametrize(
    "value",
    [
        "rest/v1/users",
        "/rest/v1/users#fragment",
        "/rest/v1/users?select=* name",
        "/rest/v1/users\x00",
    ],
)
def test_validate_refuses_an_invalid_supabase_path(tmp_path, value):
    message = _invalid_config(
        tmp_path, _supabase_payload(read_path=value)
    )

    assert "read_path" in message


@pytest.mark.parametrize(
    "anon_key",
    [None, "", "too-short", "x" * 4097, "has a space", "has\x00control", 1, []],
)
def test_validate_requires_a_valid_supabase_anon_key(tmp_path, anon_key):
    message = _invalid_config(
        tmp_path, _supabase_payload(anon_key=anon_key)
    )

    assert "anon_key" in message


def test_validate_never_echoes_the_anon_key(tmp_path):
    secret = "super-secret-anon-key with-space"

    message = _invalid_config(
        tmp_path, _supabase_payload(anon_key=secret)
    )

    assert secret not in message
    assert "super-secret-anon-key" not in message


def test_validate_refuses_an_anon_key_on_firebase(tmp_path):
    message = _invalid_config(
        tmp_path, _firebase_payload(anon_key=ANON_KEY)
    )

    assert "only valid for supabase" in message
    assert ANON_KEY not in message


# Firebase probe


def test_firebase_marker_string_and_non_empty_data_is_exposed():
    fetch = FakeFetch(
        _firebase_marker(), _firebase_data('{"users":[{"id":1}]}')
    )

    result = probe_database_rules(_firebase_config(), fetch=fetch)

    assert result["probe"] == "database_rules"
    assert result["verdict"] == EXPOSED
    assert result["cause"] is None
    assert FIREBASE_DATA_PATH in result["evidence"]
    assert "200" in result["evidence"]
    assert "non-empty" in result["evidence"]
    assert fetch.calls == [
        (
            "GET",
            FIREBASE_URL + MARKER_PATH,
            {"User-Agent": "pry/0.1"},
        ),
        (
            "GET",
            FIREBASE_URL + FIREBASE_DATA_PATH,
            {"User-Agent": "pry/0.1"},
        ),
    ]
    assert result["request"] == {
        "method": "GET",
        "url": FIREBASE_URL + FIREBASE_DATA_PATH,
        "headers": {"user-agent": "pry/0.1"},
    }
    assert result["response"]["status"] == 200
    ownership = result["response"]["ownership"]
    assert ownership["request"]["method"] == "GET"
    assert ownership["request"]["url"] == FIREBASE_URL + MARKER_PATH
    assert ownership["response"]["status"] == 200
    assert MARKER in ownership["response"]["body"]
    ProbeResult(**result)


def test_firebase_marker_dict_is_accepted():
    fetch = FakeFetch(
        _firebase_marker(json.dumps({"marker": MARKER})),
        _firebase_data('{"users":[]}'),
    )

    result = probe_database_rules(_firebase_config(), fetch=fetch)

    assert result["verdict"] == EXPOSED


@pytest.mark.parametrize(
    "body",
    ['"another-marker-value"', '{"marker":"another-marker-value"}', "[]", "{}", "not json"],
)
def test_firebase_marker_mismatch_raises_before_the_data_request(body):
    fetch = FakeFetch(_firebase_marker(body))

    with pytest.raises(DatabaseError) as exc:
        probe_database_rules(_firebase_config(), fetch=fetch)

    assert exc.value.cause == DATABASE_MARKER_MISMATCH
    assert "configured marker not found" in exc.value.message
    assert len(fetch.calls) == 1


@pytest.mark.parametrize("status", [401, 403, 404, 500])
def test_firebase_marker_rejection_raises_before_the_data_request(status):
    fetch = FakeFetch(_response(FIREBASE_URL, MARKER_PATH, "", status=status))

    with pytest.raises(DatabaseError) as exc:
        probe_database_rules(_firebase_config(), fetch=fetch)

    assert exc.value.cause == DATABASE_MARKER_UNVERIFIED
    assert str(status) in exc.value.message
    assert len(fetch.calls) == 1


def test_firebase_marker_transport_failure_raises_before_the_data_request():
    fetch = FakeFetch(
        TransportError(TARGET_UNREACHABLE, "connection refused")
    )

    with pytest.raises(DatabaseError) as exc:
        probe_database_rules(_firebase_config(), fetch=fetch)

    assert exc.value.cause == DATABASE_MARKER_UNVERIFIED
    assert "marker request failed" in exc.value.message
    assert len(fetch.calls) == 1


def test_firebase_marker_response_from_another_origin_is_unverified():
    fetch = FakeFetch(
        _firebase_marker(final_url="https://evil.invalid/pry_ownership.json")
    )

    with pytest.raises(DatabaseError) as exc:
        probe_database_rules(_firebase_config(), fetch=fetch)

    assert exc.value.cause == DATABASE_MARKER_UNVERIFIED
    assert "different origin" in exc.value.message
    assert len(fetch.calls) == 1


@pytest.mark.parametrize("status", [401, 403, 404])
def test_firebase_rejected_data_status_is_not_reproduced(status):
    fetch = FakeFetch(_firebase_marker(), _firebase_data("", status=status))

    result = probe_database_rules(_firebase_config(), fetch=fetch)

    assert result["verdict"] == NOT_REPRODUCED
    assert result["cause"] is None
    assert result["response"]["status"] == status
    assert "rejected" in result["evidence"]
    assert FIREBASE_DATA_PATH in result["evidence"]
    assert result["response"]["ownership"]["request"]["url"] == (
        FIREBASE_URL + MARKER_PATH
    )


@pytest.mark.parametrize("status", [500, 503, 302])
def test_firebase_other_non_2xx_data_status_is_unverified(status):
    fetch = FakeFetch(_firebase_marker(), _firebase_data("", status=status))

    result = probe_database_rules(_firebase_config(), fetch=fetch)

    assert result["verdict"] == UNVERIFIED
    assert result["cause"] is None
    assert "cannot confirm" in result["evidence"]
    assert result["response"]["status"] == status


@pytest.mark.parametrize("body", ["{}", "[]", '""', "null"])
def test_firebase_empty_data_is_not_reproduced(body):
    fetch = FakeFetch(_firebase_marker(), _firebase_data(body))

    result = probe_database_rules(_firebase_config(), fetch=fetch)

    assert result["verdict"] == NOT_REPRODUCED
    assert result["cause"] is None
    assert "empty" in result["evidence"]
    assert FIREBASE_DATA_PATH in result["evidence"]


@pytest.mark.parametrize(
    "body",
    ['{"users":[{"id":1}]}', "[1]", '"row"', "7", "true", "false"],
)
def test_firebase_other_non_empty_json_is_exposed(body):
    fetch = FakeFetch(_firebase_marker(), _firebase_data(body))

    result = probe_database_rules(_firebase_config(), fetch=fetch)

    assert result["verdict"] == EXPOSED
    assert "non-empty" in result["evidence"]


def test_firebase_invalid_data_json_is_not_reproduced():
    fetch = FakeFetch(_firebase_marker(), _firebase_data("not json"))

    result = probe_database_rules(_firebase_config(), fetch=fetch)

    assert result["verdict"] == NOT_REPRODUCED
    assert result["cause"] == DATABASE_INVALID
    assert "not JSON" in result["evidence"]


def test_firebase_data_transport_failure_is_unverified_without_a_response():
    fetch = FakeFetch(
        _firebase_marker(),
        TransportError(TARGET_UNREACHABLE, "connection refused"),
    )

    result = probe_database_rules(_firebase_config(), fetch=fetch)

    assert result["verdict"] == UNVERIFIED
    assert result["cause"] == TARGET_UNREACHABLE
    assert result["response"] is None
    assert "transport failure" in result["evidence"]
    ProbeResult(**result)


def test_firebase_data_from_another_origin_is_not_reproduced():
    fetch = FakeFetch(
        _firebase_marker(),
        _firebase_data(
            '{"users":[{"id":1}]}',
            final_url="https://evil.invalid/users.json",
        ),
    )

    result = probe_database_rules(_firebase_config(), fetch=fetch)

    assert result["verdict"] == NOT_REPRODUCED
    assert "different origin" in result["evidence"]
    assert result["response"]["status"] == 200


def test_the_captured_data_body_is_capped():
    body = json.dumps("x" * (BODY_LIMIT * 2))
    fetch = FakeFetch(_firebase_marker(), _firebase_data(body))

    result = probe_database_rules(_firebase_config(), fetch=fetch)

    assert result["verdict"] == EXPOSED
    assert len(result["response"]["body"]) == BODY_LIMIT


def test_captured_response_headers_are_redacted():
    headers = {
        "Set-Cookie": "sid=secret",
        "X-Api-Key": "secret-key",
        "Content-Type": "application/json",
    }
    fetch = FakeFetch(
        _firebase_marker(headers=headers),
        _firebase_data('{"users":[{"id":1}]}', headers=headers),
    )

    result = probe_database_rules(_firebase_config(), fetch=fetch)

    captured = result["response"]["ownership"]["response"]["headers"]
    assert captured["set-cookie"] == "[redacted]"
    assert captured["x-api-key"] == "[redacted]"
    assert captured["content-type"] == "application/json"


# Supabase probe


def test_supabase_sends_the_apikey_on_both_requests_and_redacts_it():
    fetch = FakeFetch(
        _supabase_marker(), _supabase_data('[{"id":1}]')
    )

    result = probe_database_rules(_supabase_config(), fetch=fetch)

    assert result["verdict"] == EXPOSED
    assert len(fetch.calls) == 2
    for _method, _url, headers in fetch.calls:
        assert headers["apikey"] == ANON_KEY
        assert "Authorization" not in headers
        assert "authorization" not in headers
    assert result["request"]["headers"]["apikey"] == "[redacted]"
    assert (
        result["response"]["ownership"]["request"]["headers"]["apikey"]
        == "[redacted]"
    )
    assert ANON_KEY not in json.dumps(result)


def test_supabase_marker_dict_is_accepted():
    fetch = FakeFetch(
        _supabase_marker(json.dumps({"marker": MARKER})),
        _supabase_data('[{"id":1}]'),
    )

    result = probe_database_rules(_supabase_config(), fetch=fetch)

    assert result["verdict"] == EXPOSED


@pytest.mark.parametrize(
    "body",
    [
        json.dumps([{"marker": "another-marker-value"}]),
        json.dumps({"marker": "another-marker-value"}),
        json.dumps(MARKER),
        "not json",
    ],
)
def test_supabase_marker_mismatch_raises_before_the_data_request(body):
    fetch = FakeFetch(_supabase_marker(body))

    with pytest.raises(DatabaseError) as exc:
        probe_database_rules(_supabase_config(), fetch=fetch)

    assert exc.value.cause == DATABASE_MARKER_MISMATCH
    assert len(fetch.calls) == 1


def test_supabase_marker_rejection_raises_before_the_data_request():
    fetch = FakeFetch(
        _response(SUPABASE_URL, SUPABASE_MARKER_PATH, "", status=403)
    )

    with pytest.raises(DatabaseError) as exc:
        probe_database_rules(_supabase_config(), fetch=fetch)

    assert exc.value.cause == DATABASE_MARKER_UNVERIFIED
    assert "403" in exc.value.message
    assert len(fetch.calls) == 1


def test_supabase_empty_row_list_is_not_reproduced():
    fetch = FakeFetch(_supabase_marker(), _supabase_data("[]"))

    result = probe_database_rules(_supabase_config(), fetch=fetch)

    assert result["verdict"] == NOT_REPRODUCED
    assert result["cause"] is None
    assert "empty" in result["evidence"]


def test_supabase_error_object_is_not_reproduced():
    fetch = FakeFetch(
        _supabase_marker(),
        _supabase_data('{"error":"permission denied"}'),
    )

    result = probe_database_rules(_supabase_config(), fetch=fetch)

    assert result["verdict"] == NOT_REPRODUCED
    assert "error" in result["evidence"]


@pytest.mark.parametrize("body", ['{"id":1}', '"row"', "7", "null"])
def test_supabase_non_row_list_json_is_not_reproduced(body):
    fetch = FakeFetch(_supabase_marker(), _supabase_data(body))

    result = probe_database_rules(_supabase_config(), fetch=fetch)

    assert result["verdict"] == NOT_REPRODUCED
    assert result["cause"] is None


def test_supabase_invalid_data_json_is_not_reproduced():
    fetch = FakeFetch(_supabase_marker(), _supabase_data("not json"))

    result = probe_database_rules(_supabase_config(), fetch=fetch)

    assert result["verdict"] == NOT_REPRODUCED
    assert result["cause"] == DATABASE_INVALID
    assert "not JSON" in result["evidence"]


@pytest.mark.parametrize("status", [401, 403, 404])
def test_supabase_rejected_data_status_is_not_reproduced(status):
    fetch = FakeFetch(_supabase_marker(), _supabase_data("", status=status))

    result = probe_database_rules(_supabase_config(), fetch=fetch)

    assert result["verdict"] == NOT_REPRODUCED
    assert result["response"]["status"] == status
    assert "rejected" in result["evidence"]


def test_supabase_data_5xx_is_unverified():
    fetch = FakeFetch(_supabase_marker(), _supabase_data("", status=503))

    result = probe_database_rules(_supabase_config(), fetch=fetch)

    assert result["verdict"] == UNVERIFIED
    assert result["cause"] is None


def test_supabase_data_transport_failure_has_no_response():
    fetch = FakeFetch(
        _supabase_marker(),
        TransportError(TARGET_UNREACHABLE, "connection refused"),
    )

    result = probe_database_rules(_supabase_config(), fetch=fetch)

    assert result["verdict"] == UNVERIFIED
    assert result["response"] is None
    assert ANON_KEY not in json.dumps(result)


def test_the_anon_key_is_redacted_from_captured_bodies():
    marker_body = json.dumps({"marker": MARKER, "echo": ANON_KEY})
    data_body = json.dumps([{"id": 1, "echo": ANON_KEY}])
    fetch = FakeFetch(
        _supabase_marker(marker_body), _supabase_data(data_body)
    )

    result = probe_database_rules(_supabase_config(), fetch=fetch)

    assert result["verdict"] == EXPOSED
    assert ANON_KEY not in json.dumps(result)
    assert "[redacted]" in result["response"]["body"]
