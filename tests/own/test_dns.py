"""DNS TXT verification tests (AT3/AT4)."""

import dns.exception
import dns.resolver
import pytest

from pry.own.dns import default_resolve_txt, verify_dns
from pry.own.errors import (
    DNS_ERROR,
    DNS_MISMATCH,
    DNS_RECORD_NOT_FOUND,
    UNSUPPORTED_TARGET,
    OwnershipError,
)
from pry.own.target import normalize_target

NONCE = "A" * 43
EXPECTED = "pry-verify=" + NONCE


def test_matching_txt_record_is_verified():
    calls = []

    def fake_resolve(name):
        calls.append(name)
        return [EXPECTED]

    verify_dns(normalize_target("https://example.com"), NONCE, resolve_txt=fake_resolve)
    assert calls == ["_pry.example.com"]


def test_any_matching_record_among_others_is_verified():
    records = ["unrelated", "  " + EXPECTED + "\n"]
    verify_dns(
        normalize_target("https://example.com"),
        NONCE,
        resolve_txt=lambda name: records,
    )


def test_wrong_record_is_mismatch():
    with pytest.raises(OwnershipError) as exc:
        verify_dns(
            normalize_target("https://example.com"),
            NONCE,
            resolve_txt=lambda name: ["pry-verify=" + "B" * 43],
        )
    assert exc.value.cause == DNS_MISMATCH


def test_empty_answer_is_not_found():
    with pytest.raises(OwnershipError) as exc:
        verify_dns(normalize_target("https://example.com"), NONCE, resolve_txt=lambda name: [])
    assert exc.value.cause == DNS_RECORD_NOT_FOUND


def test_resolver_timeout_is_dns_error():
    def fake_resolve(name):
        raise TimeoutError("timed out")

    with pytest.raises(OwnershipError) as exc:
        verify_dns(normalize_target("https://example.com"), NONCE, resolve_txt=fake_resolve)
    assert exc.value.cause == DNS_ERROR


def test_unexpected_resolver_error_is_dns_error():
    def fake_resolve(name):
        raise RuntimeError("boom")

    with pytest.raises(OwnershipError) as exc:
        verify_dns(normalize_target("https://example.com"), NONCE, resolve_txt=fake_resolve)
    assert exc.value.cause == DNS_ERROR


def test_ip_target_is_unsupported():
    with pytest.raises(OwnershipError) as exc:
        verify_dns(normalize_target("https://127.0.0.1"), NONCE, resolve_txt=lambda name: [])
    assert exc.value.cause == UNSUPPORTED_TARGET


class _Rdata:
    def __init__(self, chunks):
        self.strings = chunks


def test_chunked_txt_rdata_is_joined(monkeypatch):
    def fake_resolve(name, rdtype, lifetime):
        assert name == "_pry.example.com"
        assert rdtype == "TXT"
        return [_Rdata((b"pry-verify=", NONCE.encode("ascii")))]

    monkeypatch.setattr(dns.resolver, "resolve", fake_resolve)
    assert default_resolve_txt("_pry.example.com") == [EXPECTED]


def test_nxdomain_is_an_empty_answer(monkeypatch):
    def fake_resolve(*args, **kwargs):
        raise dns.resolver.NXDOMAIN()

    monkeypatch.setattr(dns.resolver, "resolve", fake_resolve)
    assert default_resolve_txt("_pry.example.com") == []


def test_no_answer_is_an_empty_answer(monkeypatch):
    def fake_resolve(*args, **kwargs):
        raise dns.resolver.NoAnswer()

    monkeypatch.setattr(dns.resolver, "resolve", fake_resolve)
    assert default_resolve_txt("_pry.example.com") == []


def test_default_resolver_timeout_is_dns_error(monkeypatch):
    def fake_resolve(*args, **kwargs):
        raise dns.exception.Timeout()

    monkeypatch.setattr(dns.resolver, "resolve", fake_resolve)
    with pytest.raises(OwnershipError) as exc:
        default_resolve_txt("_pry.example.com")
    assert exc.value.cause == DNS_ERROR
