"""Configured live IDOR check: two identities, two objects, three GETs.

The config holds credentials. It is read once, never stored, and the stored
request/response headers are redacted; only the requests carry the real ones.
The probe core lives in the sidecar so the live and local checks cannot drift.
"""

import json
import re
import stat
from dataclasses import dataclass
from pathlib import Path

from pry.probe.results import ProbeError
from pry.probe.scan import validate_endpoints
from pry.probe.sidecar import probe_idor as _probe_idor

IDOR_CONFIG_INVALID = "IDOR_CONFIG_INVALID"

HEADER_VALUE_LIMIT = 4096
FORBIDDEN_HEADERS = frozenset(("host", "content-length", "transfer-encoding"))
_HEADER_NAME = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")


@dataclass(frozen=True)
class IdorConfig:
    headers_a: dict
    headers_b: dict
    object_a: str
    object_b: str


def _invalid(message):
    return ProbeError(IDOR_CONFIG_INVALID, message)


def _read_config(path):
    config_path = Path(path).expanduser()
    try:
        info = config_path.stat()
    except OSError:
        raise _invalid("config file is missing or unreadable")
    if not stat.S_ISREG(info.st_mode):
        raise _invalid("config must be a regular file")
    mode = stat.S_IMODE(info.st_mode)
    if mode & 0o077:
        raise _invalid(
            "config file must not be accessible by group or other (chmod 600)"
        )
    if not mode & 0o400:
        raise _invalid("config file must be readable by its owner")
    try:
        text = config_path.read_text(encoding="utf-8")
    except OSError:
        raise _invalid("config file is unreadable")
    try:
        return json.loads(text)
    except ValueError:
        raise _invalid("config file is not valid JSON")


def _valid_headers(value, field):
    if not isinstance(value, dict) or not value:
        raise _invalid("%s must be a non-empty object of headers" % field)
    headers = {}
    for name, header_value in value.items():
        if not isinstance(name, str) or not _HEADER_NAME.match(name):
            raise _invalid("%s has an invalid header name" % field)
        if name.lower() in FORBIDDEN_HEADERS:
            raise _invalid("%s must not set the %s header" % (field, name))
        if not isinstance(header_value, str) or not header_value:
            raise _invalid(
                "%s header %s must have a non-empty string value"
                % (field, name)
            )
        if len(header_value) > HEADER_VALUE_LIMIT:
            raise _invalid(
                "%s header %s exceeds %d characters"
                % (field, name, HEADER_VALUE_LIMIT)
            )
        if any(ord(char) < 32 or ord(char) == 127 for char in header_value):
            raise _invalid(
                "%s header %s contains a control character" % (field, name)
            )
        headers[name] = header_value
    return headers


def _identity_headers(data, field):
    identity = data.get(field)
    if not isinstance(identity, dict):
        raise _invalid("%s must be an object with headers" % field)
    return _valid_headers(identity.get("headers"), field + ".headers")


def load_idor_config(path):
    """Read and validate a 0600 IDOR config; the path is never reported."""
    data = _read_config(path)
    if not isinstance(data, dict):
        raise _invalid("config must be a JSON object")
    headers_a = _identity_headers(data, "identity_a")
    headers_b = _identity_headers(data, "identity_b")
    object_a = data.get("object_a")
    object_b = data.get("object_b")
    try:
        validate_endpoints([object_a, object_b])
    except ProbeError as exc:
        raise _invalid(
            "object_a and object_b must be path-only: %s" % exc.message
        ) from exc
    return IdorConfig(
        headers_a=headers_a,
        headers_b=headers_b,
        object_a=object_a,
        object_b=object_b,
    )


def probe_idor(base_url, config, fetch=None):
    """Run A->A and B->B controls, then A->B; only a clean cross is EXPOSED."""
    return _probe_idor(
        base_url,
        config.headers_a,
        config.headers_b,
        config.object_a,
        config.object_b,
        fetch=fetch,
    )
