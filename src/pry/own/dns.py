"""DNS TXT ownership verification."""

from typing import Callable, List

import dns.exception
import dns.resolver

from pry.own.errors import (
    DNS_ERROR,
    DNS_MISMATCH,
    DNS_RECORD_NOT_FOUND,
    UNSUPPORTED_TARGET,
    OwnershipError,
)
from pry.own.target import Target

TxtResolver = Callable[[str], List[str]]


def default_resolve_txt(name: str) -> List[str]:
    try:
        answer = dns.resolver.resolve(name, "TXT", lifetime=5.0)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return []
    except dns.exception.Timeout as exc:
        raise OwnershipError(DNS_ERROR, "DNS lookup timed out") from exc
    except Exception as exc:
        raise OwnershipError(DNS_ERROR, "DNS lookup failed: %s" % exc) from exc

    return [
        b"".join(rdata.strings).decode("utf-8", "replace")
        for rdata in answer
    ]


def verify_dns(
    target: Target,
    challenge: str,
    resolve_txt: TxtResolver = default_resolve_txt,
) -> None:
    if target.is_ip:
        raise OwnershipError(UNSUPPORTED_TARGET, "DNS verification requires a hostname")

    expected = "pry-verify=" + challenge
    try:
        answers = resolve_txt(target.dns_name)
    except OwnershipError:
        raise
    except Exception as exc:
        raise OwnershipError(DNS_ERROR, "DNS lookup failed: %s" % exc) from exc

    if not answers:
        raise OwnershipError(
            DNS_RECORD_NOT_FOUND, "no TXT record at %s" % target.dns_name
        )
    if any(value.strip() == expected for value in answers):
        return
    raise OwnershipError(DNS_MISMATCH, "TXT record does not match the challenge")
