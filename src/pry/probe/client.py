"""Execute the read-only sidecar through Docker and parse its result."""

import json
from typing import List

from pry.probe.headers import HEADER_PROBE, parse_headers_result
from pry.probe.rate_limit import (
    RATE_LIMIT,
    RateLimitConfig,
    parse_rate_limit_result,
)
from pry.probe.results import UNVERIFIED, VERDICTS, ProbeResult

SIDECAR_PATH = "/pry/sidecar.py"
IDOR_CONFIG_PATH = "/pry-config/idor.json"
EXEC_FAILED = "EXEC_FAILED"
EXEC_TIMEOUT = "EXEC_TIMEOUT"
INVALID_RESULT = "INVALID_RESULT"
UNKNOWN_VERDICT = "UNKNOWN_VERDICT"
RATE_LIMIT_TIMEOUT = 120
PROBE_ORDER = ("cors", "errors", "secrets")


def _text(raw) -> str:
    if raw is None:
        return ""
    if isinstance(raw, bytes):
        return raw.decode("utf-8", "replace")
    return str(raw)


def _detail(result) -> str:
    text = _text(result.stderr or result.stdout).strip()
    return (text or "exit code %d" % result.returncode)[:500]


def _unverified(probe, cause, evidence, base_url) -> ProbeResult:
    return ProbeResult(
        probe=probe,
        verdict=UNVERIFIED,
        cause=cause,
        evidence=evidence,
        request={"method": "EXEC", "url": base_url, "headers": {}},
        response=None,
    )


def _rate_limit_unverified(cause, evidence, base_url, path) -> dict:
    url = str(path)
    if isinstance(path, str) and path.startswith("/"):
        url = base_url.rstrip("/") + path
    return {
        "probe": RATE_LIMIT,
        "status": UNVERIFIED,
        "evidence": "rate-limit probe failed: %s: %s" % (cause, evidence),
        "request": {"method": "GET", "url": url, "headers": {}},
        "response": None,
        "count": 0,
        "statuses": [],
    }


def _headers_unverified(cause, evidence, base_url) -> dict:
    return {
        "probe": HEADER_PROBE,
        "status": UNVERIFIED,
        "evidence": "headers probe failed: %s: %s" % (cause, evidence),
        "request": {
            "method": "GET",
            "url": base_url.rstrip("/") + "/",
            "headers": {},
        },
        "response": None,
        "missing": [],
        "present": [],
    }


class ProbeClient:
    """Run one sidecar probe and turn its stdout into a ProbeResult."""

    def __init__(self, docker, sidecar, base_url, timeout=20):
        self.docker = docker
        self.sidecar = sidecar
        self.base_url = base_url
        self.timeout = timeout

    def run(self, probe: str, endpoint=None) -> ProbeResult:
        command = ["python", SIDECAR_PATH, probe, self.base_url]
        if probe == "unauth" and endpoint is not None:
            command.append(endpoint)
        return self._exec(probe, command, self.timeout)

    def run_idor(self) -> ProbeResult:
        """Exec the configured IDOR check; a failure is UNVERIFIED, not a raise."""
        return self._exec(
            "idor",
            [
                "python",
                SIDECAR_PATH,
                "idor",
                self.base_url,
                IDOR_CONFIG_PATH,
            ],
            self.timeout,
        )

    def _exec(self, probe: str, command: List[str], timeout: int) -> ProbeResult:
        try:
            result = self.docker.exec(self.sidecar, command, timeout=timeout)
        except Exception as exc:
            return _unverified(
                probe,
                EXEC_FAILED,
                "cannot exec sidecar: %s" % exc,
                self.base_url,
            )
        if result.timed_out:
            return _unverified(
                probe,
                EXEC_TIMEOUT,
                "probe timed out after %ss" % timeout,
                self.base_url,
            )
        if result.returncode != 0:
            return _unverified(probe, EXEC_FAILED, _detail(result), self.base_url)
        try:
            payload = json.loads(_text(result.stdout))
        except ValueError:
            return _unverified(
                probe,
                INVALID_RESULT,
                "sidecar did not print valid JSON",
                self.base_url,
            )
        if not isinstance(payload, dict):
            return _unverified(
                probe,
                INVALID_RESULT,
                "sidecar printed JSON that is not an object",
                self.base_url,
            )
        if payload.get("verdict") not in VERDICTS:
            return _unverified(
                probe,
                UNKNOWN_VERDICT,
                "sidecar returned an unknown verdict: %r"
                % (payload.get("verdict"),),
                self.base_url,
            )
        try:
            return ProbeResult(**payload)
        except (TypeError, ValueError) as exc:
            return _unverified(
                probe,
                INVALID_RESULT,
                "sidecar returned an invalid result: %s" % exc,
                self.base_url,
            )

    def run_all(self) -> List[ProbeResult]:
        return [self.run(probe) for probe in PROBE_ORDER]

    def run_rate_limit(self, path: str, count: int) -> dict:
        """Exec the sidecar observation; a failure is an UNVERIFIED dict, not a raise."""
        if isinstance(count, bool) or not isinstance(count, int):
            return _rate_limit_unverified(
                INVALID_RESULT,
                "invalid rate-limit count: %r" % (count,),
                self.base_url,
                path,
            )
        command = [
            "python",
            SIDECAR_PATH,
            RATE_LIMIT,
            self.base_url,
            path,
            str(count),
        ]
        try:
            result = self.docker.exec(
                self.sidecar, command, timeout=RATE_LIMIT_TIMEOUT
            )
        except Exception as exc:
            return _rate_limit_unverified(
                EXEC_FAILED,
                "cannot exec sidecar: %s" % exc,
                self.base_url,
                path,
            )
        if result.timed_out:
            return _rate_limit_unverified(
                EXEC_TIMEOUT,
                "probe timed out after %ss" % RATE_LIMIT_TIMEOUT,
                self.base_url,
                path,
            )
        if result.returncode != 0:
            return _rate_limit_unverified(
                EXEC_FAILED, _detail(result), self.base_url, path
            )
        try:
            payload = json.loads(_text(result.stdout))
        except ValueError:
            return _rate_limit_unverified(
                INVALID_RESULT,
                "sidecar did not print valid JSON",
                self.base_url,
                path,
            )
        if not isinstance(payload, dict):
            return _rate_limit_unverified(
                INVALID_RESULT,
                "sidecar printed JSON that is not an object",
                self.base_url,
                path,
            )
        return parse_rate_limit_result(
            payload, RateLimitConfig(endpoint=path, count=count)
        )

    def run_headers(self) -> dict:
        """Exec the sidecar header observation; a failure is UNVERIFIED, not a raise."""
        command = ["python", SIDECAR_PATH, HEADER_PROBE, self.base_url]
        try:
            result = self.docker.exec(
                self.sidecar, command, timeout=self.timeout
            )
        except Exception as exc:
            return _headers_unverified(
                EXEC_FAILED, "cannot exec sidecar: %s" % exc, self.base_url
            )
        if result.timed_out:
            return _headers_unverified(
                EXEC_TIMEOUT,
                "probe timed out after %ss" % self.timeout,
                self.base_url,
            )
        if result.returncode != 0:
            return _headers_unverified(
                EXEC_FAILED, _detail(result), self.base_url
            )
        try:
            payload = json.loads(_text(result.stdout))
        except ValueError:
            return _headers_unverified(
                INVALID_RESULT,
                "sidecar did not print valid JSON",
                self.base_url,
            )
        return parse_headers_result(payload)
