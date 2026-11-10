"""Declared local Level 2 write config, validated before any Docker work.

The config names a write and the read that proves it landed. It is 0600, is
never reported, and the unique marker is generated inside the sandbox.
"""

import json
import stat
from dataclasses import dataclass
from pathlib import Path

from pry.probe.results import ProbeError

WRITE_CONFIG_INVALID = "WRITE_CONFIG_INVALID"
WRITE_METHODS = ("POST", "PUT", "PATCH")
WRITE_MARKER = "{{marker}}"
WRITE_BODY_LIMIT = 4096
WRITE_CONTENT_TYPE_LIMIT = 128
WRITE_CONTENT_TYPE_DEFAULT = "application/json"
ENDPOINT_LIMIT = 2048


@dataclass(frozen=True)
class WriteConfig:
    method: str
    endpoint: str
    body: str
    verify_endpoint: str
    verify_contains: str
    content_type: str = WRITE_CONTENT_TYPE_DEFAULT


def _invalid(message):
    return ProbeError(WRITE_CONFIG_INVALID, message)


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


def _path(value, field):
    from pry.probe.scan import validate_endpoints

    try:
        validate_endpoints([value])
    except ProbeError as exc:
        raise _invalid("%s must be path-only: %s" % (field, exc.message)) from exc
    if "?" in value or "#" in value:
        raise _invalid("%s must not include a query or fragment" % field)
    return value


def validate_write_config(data):
    """Return a WriteConfig, or fail with WRITE_CONFIG_INVALID."""
    if not isinstance(data, dict):
        raise _invalid("config must be a JSON object")
    method = data.get("method")
    if not isinstance(method, str) or method.upper() not in WRITE_METHODS:
        raise _invalid("method must be one of POST, PUT, or PATCH")
    endpoint = _path(data.get("endpoint"), "endpoint")
    body = data.get("body")
    if not isinstance(body, str) or not 1 <= len(body) <= WRITE_BODY_LIMIT:
        raise _invalid(
            "body must be a string of 1..%d characters" % WRITE_BODY_LIMIT
        )
    if WRITE_MARKER not in body:
        raise _invalid("body must contain %s" % WRITE_MARKER)
    verify_endpoint = _path(data.get("verify_endpoint"), "verify_endpoint")
    verify_contains = data.get("verify_contains", WRITE_MARKER)
    if not isinstance(verify_contains, str) or WRITE_MARKER not in verify_contains:
        raise _invalid(
            "verify_contains must be a string containing %s" % WRITE_MARKER
        )
    content_type = data.get("content_type", WRITE_CONTENT_TYPE_DEFAULT)
    if (
        not isinstance(content_type, str)
        or not content_type
        or len(content_type) > WRITE_CONTENT_TYPE_LIMIT
        or any(ord(char) < 32 or ord(char) == 127 for char in content_type)
    ):
        raise _invalid(
            "content_type must be a non-empty string of at most %d characters "
            "with no control characters" % WRITE_CONTENT_TYPE_LIMIT
        )
    return WriteConfig(
        method=method.upper(),
        endpoint=endpoint,
        body=body,
        verify_endpoint=verify_endpoint,
        verify_contains=verify_contains,
        content_type=content_type,
    )


def load_write_config(path):
    """Read and validate a 0600 write config; the path is never reported."""
    return validate_write_config(_read_config(path))
