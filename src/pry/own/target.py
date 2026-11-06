"""Normalize and validate targets before anything is verified or scanned."""

import ipaddress
from dataclasses import dataclass
from typing import Optional
from urllib.parse import urlsplit

from pry.own.errors import UNSUPPORTED_TARGET, OwnershipError

_DEFAULT_PORTS = {"http": 80, "https": 443}


@dataclass(frozen=True)
class Target:
    origin: str
    scheme: str
    host: str
    port: Optional[int]
    is_loopback: bool
    is_ip: bool

    @property
    def dns_name(self) -> str:
        return "_pry." + self.host

    @property
    def well_known_url(self) -> str:
        return self.origin + "/.well-known/pry-ownership.txt"


def normalize_target(raw: str) -> Target:
    text = raw.strip()
    if "://" not in text:
        text = "https://" + text

    try:
        parts = urlsplit(text)
        port = parts.port
    except ValueError as exc:
        raise OwnershipError(UNSUPPORTED_TARGET, "invalid target: %s" % raw) from exc

    scheme = parts.scheme.lower()
    if scheme not in _DEFAULT_PORTS:
        raise OwnershipError(UNSUPPORTED_TARGET, "unsupported scheme: %s" % scheme)
    if "@" in parts.netloc:
        raise OwnershipError(UNSUPPORTED_TARGET, "userinfo is not allowed")

    host = parts.hostname
    if not host:
        raise OwnershipError(UNSUPPORTED_TARGET, "missing host")
    host = host.lower().rstrip(".")

    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        ip = None

    if ip is None:
        try:
            host = host.encode("idna").decode("ascii")
        except UnicodeError as exc:
            raise OwnershipError(UNSUPPORTED_TARGET, "invalid host: %s" % host) from exc
        if any(char.isspace() for char in host):
            raise OwnershipError(UNSUPPORTED_TARGET, "invalid host: %s" % host)
    else:
        host = str(ip)

    if port == _DEFAULT_PORTS[scheme]:
        port = None

    display_host = "[%s]" % host if ip is not None and ":" in host else host
    origin = "%s://%s" % (scheme, display_host)
    if port is not None:
        origin += ":%d" % port

    is_loopback = host == "localhost" or (ip is not None and ip.is_loopback)

    return Target(
        origin=origin,
        scheme=scheme,
        host=host,
        port=port,
        is_loopback=is_loopback,
        is_ip=ip is not None,
    )
