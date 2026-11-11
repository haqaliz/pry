"""Provider database open-rule checks with a marker ownership attestation.

The 0600 config names a Firebase RTDB or Supabase REST project, a marker the
owner placed, and one declared data path. The marker is read first; a mismatch
or denial stops the run before the data request.
"""

import json
import stat
import urllib.parse
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from pry.probe.results import EXPOSED, NOT_REPRODUCED, UNVERIFIED, ProbeError
from pry.probe.sidecar import BODY_LIMIT, TransportError, urllib_fetch

DATABASE_CONFIG_INVALID = "DATABASE_CONFIG_INVALID"
DATABASE_MARKER_CONFIRMATION_REQUIRED = "DATABASE_MARKER_CONFIRMATION_REQUIRED"
DATABASE_MARKER_MISMATCH = "DATABASE_MARKER_MISMATCH"
DATABASE_MARKER_UNVERIFIED = "DATABASE_MARKER_UNVERIFIED"
DATABASE_INVALID = "DATABASE_INVALID"

DATABASE_RULES_PROBE = "database_rules"
PROVIDERS = ("firebase-rtdb", "supabase")
FIREBASE = "firebase-rtdb"
SUPABASE = "supabase"
MARKER_MIN = 16
MARKER_MAX = 256
PATH_LIMIT = 2048
ANON_KEY_MIN = 10
ANON_KEY_MAX = 4096
USER_AGENT = "pry/0.1"
LOOPBACK_HOSTS = frozenset(("127.0.0.1", "localhost", "::1"))
REDACTED = "[redacted]"
REDACTED_HEADERS = frozenset(
    (
        "authorization",
        "cookie",
        "set-cookie",
        "x-api-key",
        "proxy-authorization",
        "apikey",
    )
)


@dataclass(frozen=True)
class DatabaseConfig:
    provider: str
    url: str
    marker_path: str
    marker: str
    read_path: str
    anon_key: Optional[str] = None


class DatabaseError(Exception):
    """A marker or database response that stops the check, with a cause."""

    def __init__(self, cause, message):
        super().__init__(message)
        self.cause = cause
        self.message = message

    def __str__(self):
        return "%s: %s" % (self.cause, self.message)


def _invalid(message):
    return ProbeError(DATABASE_CONFIG_INVALID, message)


def _has_control(value):
    return any(ord(char) < 32 or ord(char) == 127 for char in value)


def _has_space_or_control(value):
    return any(
        char.isspace() or ord(char) < 32 or ord(char) == 127 for char in value
    )


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


def _url(value):
    if (
        not isinstance(value, str)
        or not value
        or _has_space_or_control(value)
    ):
        raise _invalid("url must be an absolute http(s) URL")
    try:
        parts = urllib.parse.urlsplit(value)
        hostname = parts.hostname
        parts.port
    except ValueError:
        raise _invalid("url must be an absolute http(s) URL")
    scheme = parts.scheme.lower()
    if scheme not in ("http", "https") or not hostname:
        raise _invalid("url must be an absolute http(s) URL")
    if parts.username is not None or parts.password is not None:
        raise _invalid("url must not contain userinfo")
    if parts.query or parts.fragment:
        raise _invalid("url must not contain a query or fragment")
    if parts.path not in ("", "/"):
        raise _invalid("url must not contain a path")
    if scheme != "https" and hostname not in LOOPBACK_HOSTS:
        raise _invalid("url must use HTTPS unless the host is loopback")
    return value.rstrip("/")


def _marker(value):
    if (
        not isinstance(value, str)
        or not MARKER_MIN <= len(value) <= MARKER_MAX
        or _has_control(value)
    ):
        raise _invalid(
            "marker must be a string of %d..%d characters with no control "
            "characters" % (MARKER_MIN, MARKER_MAX)
        )
    return value


def _path(value, field, provider):
    if not isinstance(value, str) or not 1 <= len(value) <= PATH_LIMIT:
        raise _invalid(
            "%s must be a string of 1..%d characters" % (field, PATH_LIMIT)
        )
    if not value.startswith("/"):
        raise _invalid("%s must start with '/'" % field)
    if "://" in value:
        raise _invalid("%s must be a path, not a URL" % field)
    if _has_space_or_control(value):
        raise _invalid(
            "%s must not contain whitespace or control characters" % field
        )
    if provider == FIREBASE:
        if "?" in value or "#" in value:
            raise _invalid(
                "%s must not include a query or fragment" % field
            )
        if not value.endswith(".json"):
            value += ".json"
    elif "#" in value:
        raise _invalid("%s must not include a fragment" % field)
    return value


def _anon_key(value, provider):
    if provider != SUPABASE:
        if value is not None:
            raise _invalid("anon_key is only valid for supabase")
        return None
    if (
        not isinstance(value, str)
        or not ANON_KEY_MIN <= len(value) <= ANON_KEY_MAX
        or _has_space_or_control(value)
    ):
        raise _invalid(
            "anon_key must be a string of %d..%d characters with no "
            "whitespace or control characters for supabase"
            % (ANON_KEY_MIN, ANON_KEY_MAX)
        )
    return value


def validate_database_config(data):
    """Return a DatabaseConfig, or fail with DATABASE_CONFIG_INVALID."""
    if not isinstance(data, dict):
        raise _invalid("config must be a JSON object")
    provider = data.get("provider")
    if provider not in PROVIDERS:
        raise _invalid("provider must be firebase-rtdb or supabase")
    url = _url(data.get("url"))
    marker = _marker(data.get("marker"))
    marker_path = _path(data.get("marker_path"), "marker_path", provider)
    read_path = _path(data.get("read_path"), "read_path", provider)
    anon_key = _anon_key(data.get("anon_key"), provider)
    return DatabaseConfig(
        provider=provider,
        url=url,
        marker_path=marker_path,
        marker=marker,
        read_path=read_path,
        anon_key=anon_key,
    )


def load_database_config(path):
    """Read and validate a 0600 database config; the path is never reported."""
    return validate_database_config(_read_config(path))


def _origin(url):
    parts = urllib.parse.urlsplit(url or "")
    return (parts.scheme.lower(), parts.netloc.lower())


def _same_origin(base_url, url):
    return _origin(base_url) == _origin(url)


def _redact_headers(headers):
    if not isinstance(headers, dict):
        return {}
    return {
        str(name).lower(): REDACTED
        if str(name).lower() in REDACTED_HEADERS
        else str(value)
        for name, value in headers.items()
    }


def _redact_text(text, config):
    text = str(text or "")
    if config.anon_key:
        text = text.replace(config.anon_key, REDACTED)
    return text


def _request_payload(url, headers):
    return {"method": "GET", "url": url, "headers": _redact_headers(headers)}


def _response_payload(response, config):
    return {
        "status": response.status,
        "headers": _redact_headers(response.headers),
        "body": _redact_text(
            (response.body or "")[:BODY_LIMIT], config
        ),
    }


def _request_headers(config):
    headers = {"User-Agent": USER_AGENT}
    if config.provider == SUPABASE:
        headers["apikey"] = config.anon_key
    return headers


def _marker_matches(config, body):
    try:
        value = json.loads(body or "")
    except ValueError:
        return False
    if config.provider == FIREBASE:
        if isinstance(value, str):
            return value == config.marker
        if isinstance(value, dict):
            return value.get("marker") == config.marker
        return False
    if isinstance(value, list):
        return any(
            isinstance(row, dict) and row.get("marker") == config.marker
            for row in value
        )
    if isinstance(value, dict):
        return value.get("marker") == config.marker
    return False


def _result(
    verdict,
    cause,
    evidence,
    url,
    headers,
    response,
    config,
    ownership,
):
    payload = {
        "probe": DATABASE_RULES_PROBE,
        "verdict": verdict,
        "cause": cause,
        "evidence": evidence,
        "request": _request_payload(url, headers),
        "response": None,
    }
    if response is not None:
        captured = _response_payload(response, config)
        captured["ownership"] = ownership
        payload["response"] = captured
    return payload


def _marker_payload(config, fetch):
    url = config.url + config.marker_path
    headers = _request_headers(config)
    try:
        response = fetch("GET", url, dict(headers))
    except TransportError as exc:
        raise DatabaseError(
            DATABASE_MARKER_UNVERIFIED,
            "marker request failed: %s" % (exc.message or "request failed"),
        )
    if not 200 <= response.status < 300:
        raise DatabaseError(
            DATABASE_MARKER_UNVERIFIED,
            "marker path returned status %d" % response.status,
        )
    if not _same_origin(config.url, response.final_url):
        raise DatabaseError(
            DATABASE_MARKER_UNVERIFIED,
            "marker path returned a response from a different origin",
        )
    if not _marker_matches(config, response.body):
        raise DatabaseError(
            DATABASE_MARKER_MISMATCH,
            "configured marker not found; place it in the database and retry",
        )
    return {
        "request": _request_payload(url, headers),
        "response": _response_payload(response, config),
    }


def _firebase_verdict(body):
    try:
        value = json.loads(body or "")
    except ValueError:
        return (
            NOT_REPRODUCED,
            DATABASE_INVALID,
            "with a body that is not JSON",
        )
    if value is None or value == "" or value == {} or value == []:
        return NOT_REPRODUCED, None, "with empty JSON data"
    return (
        EXPOSED,
        None,
        "with non-empty JSON data and no credentials",
    )


def _supabase_verdict(body):
    try:
        value = json.loads(body or "")
    except ValueError:
        return (
            NOT_REPRODUCED,
            DATABASE_INVALID,
            "with a body that is not JSON",
        )
    if isinstance(value, list):
        if value:
            return (
                EXPOSED,
                None,
                "with a non-empty JSON row list and no credentials",
            )
        return NOT_REPRODUCED, None, "with an empty JSON row list"
    if isinstance(value, dict) and "error" in value:
        return NOT_REPRODUCED, None, "with a JSON error object"
    return NOT_REPRODUCED, None, "with JSON that is not a row list"


def probe_database_rules(config, fetch=None):
    """Read the marker, then one declared data path; decide read exposure."""
    fetch = fetch if fetch is not None else urllib_fetch
    ownership = _marker_payload(config, fetch)
    url = config.url + config.read_path
    headers = _request_headers(config)
    try:
        response = fetch("GET", url, dict(headers))
    except TransportError as exc:
        return _result(
            UNVERIFIED,
            exc.cause,
            "transport failure: %s" % (exc.message or "request failed"),
            url,
            headers,
            None,
            config,
            ownership,
        )

    path = config.read_path
    if response.status in (401, 403, 404):
        return _result(
            NOT_REPRODUCED,
            None,
            "declared data path %s returned status %d; the request was "
            "rejected" % (path, response.status),
            url,
            headers,
            response,
            config,
            ownership,
        )
    if not 200 <= response.status < 300:
        return _result(
            UNVERIFIED,
            None,
            "declared data path %s returned status %d; cannot confirm the "
            "check" % (path, response.status),
            url,
            headers,
            response,
            config,
            ownership,
        )
    if not _same_origin(config.url, response.final_url):
        return _result(
            NOT_REPRODUCED,
            None,
            "declared data path %s returned a response from a different "
            "origin; the response is not evidence" % path,
            url,
            headers,
            response,
            config,
            ownership,
        )

    if config.provider == FIREBASE:
        verdict, cause, detail = _firebase_verdict(response.body)
    else:
        verdict, cause, detail = _supabase_verdict(response.body)
    return _result(
        verdict,
        cause,
        "declared data path %s returned status %d %s"
        % (path, response.status, detail),
        url,
        headers,
        response,
        config,
        ownership,
    )
