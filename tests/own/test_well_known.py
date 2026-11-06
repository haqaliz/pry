"""Well-known file verification tests (AT5/AT6)."""

import pytest

from pry.own.errors import (
    INSECURE_TRANSPORT,
    WELL_KNOWN_ERROR,
    WELL_KNOWN_MISMATCH,
    WELL_KNOWN_NOT_FOUND,
    WELL_KNOWN_REDIRECT,
    OwnershipError,
)
from pry.own.target import normalize_target
from pry.own.well_known import FetchResult, default_fetch, verify_well_known

NONCE = "A" * 43
EXPECTED = ("pry-verify=" + NONCE).encode("ascii")
PATH = "/.well-known/pry-ownership.txt"


def test_exact_body_verifies(http_server):
    base_url, routes = http_server
    routes[PATH] = (200, {}, EXPECTED)

    verify_well_known(normalize_target(base_url), NONCE)


def test_missing_file_is_not_found(http_server):
    base_url, routes = http_server

    with pytest.raises(OwnershipError) as exc:
        verify_well_known(normalize_target(base_url), NONCE)
    assert exc.value.cause == WELL_KNOWN_NOT_FOUND


def test_wrong_body_is_mismatch(http_server):
    base_url, routes = http_server
    routes[PATH] = (200, {}, b"pry-verify=" + b"B" * 43)

    with pytest.raises(OwnershipError) as exc:
        verify_well_known(normalize_target(base_url), NONCE)
    assert exc.value.cause == WELL_KNOWN_MISMATCH


def test_non_200_response_is_error(http_server):
    base_url, routes = http_server
    routes[PATH] = (500, {}, b"oops")

    with pytest.raises(OwnershipError) as exc:
        verify_well_known(normalize_target(base_url), NONCE)
    assert exc.value.cause == WELL_KNOWN_ERROR


def test_cross_origin_final_url_is_redirect_error():
    target = normalize_target("https://example.com")
    result = FetchResult(200, "https://evil.example" + PATH, EXPECTED)

    with pytest.raises(OwnershipError) as exc:
        verify_well_known(target, NONCE, fetch=lambda url: result)
    assert exc.value.cause == WELL_KNOWN_REDIRECT


def test_same_origin_redirect_is_followed(http_server):
    base_url, routes = http_server
    routes[PATH] = (302, {"Location": "/redirected"}, b"")
    routes["/redirected"] = (200, {}, EXPECTED)

    verify_well_known(normalize_target(base_url), NONCE)


def test_cross_port_redirect_is_rejected(http_server):
    base_url, routes = http_server
    routes[PATH] = (302, {"Location": "http://127.0.0.1:1" + PATH}, b"")

    with pytest.raises(OwnershipError) as exc:
        verify_well_known(normalize_target(base_url), NONCE)
    assert exc.value.cause == WELL_KNOWN_REDIRECT


def test_insecure_transport_rejected_without_fetching():
    def fetch(url):
        raise AssertionError("fetch must not run for insecure targets")

    with pytest.raises(OwnershipError) as exc:
        verify_well_known(normalize_target("http://example.com"), NONCE, fetch=fetch)
    assert exc.value.cause == INSECURE_TRANSPORT


def test_injected_timeout_is_error():
    def fetch(url):
        raise TimeoutError("timed out")

    with pytest.raises(OwnershipError) as exc:
        verify_well_known(normalize_target("https://example.com"), NONCE, fetch=fetch)
    assert exc.value.cause == WELL_KNOWN_ERROR


def test_oversized_body_is_error(http_server):
    base_url, routes = http_server
    routes[PATH] = (200, {}, b"x" * 4097)

    with pytest.raises(OwnershipError) as exc:
        verify_well_known(normalize_target(base_url), NONCE)
    assert exc.value.cause == WELL_KNOWN_ERROR


def test_default_fetch_returns_status_and_body(http_server):
    base_url, routes = http_server
    routes[PATH] = (200, {}, EXPECTED)

    result = default_fetch(base_url + PATH)
    assert result.status == 200
    assert result.body == EXPECTED
    assert result.final_url == base_url + PATH


def test_default_fetch_maps_404_to_result(http_server):
    base_url, routes = http_server

    result = default_fetch(base_url + PATH)
    assert result.status == 404
