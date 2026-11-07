"""Probe result model, redaction, and atomic results.json output."""

import json
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

EXPOSED = "EXPOSED"
NOT_REPRODUCED = "NOT_REPRODUCED"
UNVERIFIED = "UNVERIFIED"
VERDICTS = (EXPOSED, NOT_REPRODUCED, UNVERIFIED)

BODY_LIMIT = 4096
RESULTS_FILE = "results.json"
RESULTS_FAILED = "RESULTS_FAILED"


class ProbeError(Exception):
    """A probe failure with a stable, machine-readable cause."""

    def __init__(self, cause: str, message: str) -> None:
        super().__init__(message)
        self.cause = cause
        self.message = message

    def __str__(self) -> str:
        return "%s: %s" % (self.cause, self.message)


def normalize_headers(headers) -> dict:
    """Return headers with lowercase names and string values."""
    if headers is None:
        return {}
    return {str(name).lower(): str(value) for name, value in headers.items()}


def _body_text(body) -> str:
    if body is None:
        return ""
    if isinstance(body, bytes):
        return body.decode("utf-8", "replace")[:BODY_LIMIT]
    return str(body)[:BODY_LIMIT]


@dataclass(frozen=True)
class ProbeResult:
    probe: str
    verdict: str
    cause: Optional[str]
    evidence: str
    request: dict
    response: Optional[dict]
    proof: Optional[str] = None

    def __post_init__(self):
        if self.verdict not in VERDICTS:
            raise ValueError("unknown verdict: %r" % (self.verdict,))
        request = dict(self.request)
        request["headers"] = normalize_headers(request.get("headers"))
        response = self.response
        if response is not None:
            response = dict(response)
            response["headers"] = normalize_headers(response.get("headers"))
            response["body"] = _body_text(response.get("body"))
        object.__setattr__(self, "request", request)
        object.__setattr__(self, "response", response)


@dataclass(frozen=True)
class ScanResult:
    version: int
    target: dict
    results: list
    summary: dict
    created_at: str


def summarize(results) -> dict:
    """Count each verdict; every verdict is present, even at zero."""
    counts = {verdict: 0 for verdict in VERDICTS}
    for result in results:
        if result.verdict not in counts:
            raise ValueError("unknown verdict: %r" % (result.verdict,))
        counts[result.verdict] += 1
    return counts


def redact_secret(text: str, key: str) -> str:
    """Replace everything after ``key=`` or ``key:`` with ``[redacted]``."""
    pattern = re.compile(
        r"(?im)^([^\n]*?\b%s\b[^\n]*?[=:][ \t]*)([^\n]*)$" % re.escape(key)
    )
    return pattern.sub(lambda match: match.group(1) + "[redacted]", text)


def redact_urls(text: str) -> str:
    """Hide userinfo in any URL while keeping scheme, host, and path."""
    pattern = re.compile(r"(?i)\b([a-z][a-z0-9+.\-]*://)[^/\s@]+@")
    return pattern.sub(r"\1[redacted]@", text)


def write_results(run_dir, data) -> Path:
    """Atomically write sorted results.json at 0600."""
    run_dir = Path(run_dir)
    target = run_dir / RESULTS_FILE
    temp = run_dir / (RESULTS_FILE + ".tmp")
    try:
        payload = json.dumps(data, sort_keys=True, indent=2) + "\n"
        temp.write_text(payload, encoding="utf-8")
        os.chmod(str(temp), 0o600)
        os.replace(str(temp), str(target))
    except (OSError, TypeError, ValueError) as exc:
        try:
            temp.unlink()
        except OSError:
            pass
        raise ProbeError(
            RESULTS_FAILED, "cannot write results: %s" % exc
        ) from exc
    return target
