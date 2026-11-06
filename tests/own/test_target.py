"""Target normalization tests (AT1/AT2)."""

import pytest

from pry.own.errors import UNSUPPORTED_TARGET, OwnershipError
from pry.own.target import normalize_target


def test_bare_host_defaults_to_https():
    target = normalize_target("example.com")
    assert target.origin == "https://example.com"
    assert target.host == "example.com"
    assert target.scheme == "https"
    assert target.port is None
    assert target.is_loopback is False


@pytest.mark.parametrize(
    "raw",
    [
        "example.com",
        "https://EXAMPLE.com:443/",
        "https://example.com./app?x=1#f",
    ],
)
def test_equivalent_hosts_normalize_to_same_origin(raw):
    target = normalize_target(raw)
    assert target.origin == "https://example.com"
    assert target.host == "example.com"
    assert target.port is None


def test_non_default_port_is_kept():
    target = normalize_target("http://example.com:8080/app")
    assert target.origin == "http://example.com:8080"
    assert target.port == 8080


def test_default_http_port_is_dropped():
    target = normalize_target("http://example.com:80/app")
    assert target.origin == "http://example.com"
    assert target.port is None


def test_ipv6_loopback_origin_keeps_brackets():
    target = normalize_target("http://[::1]:8000")
    assert target.origin == "http://[::1]:8000"
    assert target.host == "::1"
    assert target.scheme == "http"
    assert target.port == 8000
    assert target.is_ip is True
    assert target.is_loopback is True


def test_localhost_is_loopback():
    target = normalize_target("localhost")
    assert target.origin == "https://localhost"
    assert target.is_loopback is True
    assert target.is_ip is False


def test_ipv4_loopback_is_recognized():
    target = normalize_target("https://127.0.0.1")
    assert target.is_ip is True
    assert target.is_loopback is True


def test_public_ip_is_not_loopback():
    target = normalize_target("https://203.0.113.10")
    assert target.is_ip is True
    assert target.is_loopback is False


@pytest.mark.parametrize(
    "raw",
    [
        "ftp://example.com",
        "https://user:pass@example.com",
        "https://",
        "https://exa mple.com",
        "https://example.com:99999",
    ],
)
def test_unsupported_targets_are_rejected(raw):
    with pytest.raises(OwnershipError) as exc:
        normalize_target(raw)
    assert exc.value.cause == UNSUPPORTED_TARGET


def test_dns_name_and_well_known_url():
    target = normalize_target("https://example.com")
    assert target.dns_name == "_pry.example.com"
    assert target.well_known_url == "https://example.com/.well-known/pry-ownership.txt"
