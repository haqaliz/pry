"""Execute the read-only sidecar through Docker and parse its result."""

import json
from typing import List

from pry.probe.results import UNVERIFIED, VERDICTS, ProbeResult

SIDECAR_PATH = "/pry/sidecar.py"
EXEC_FAILED = "EXEC_FAILED"
EXEC_TIMEOUT = "EXEC_TIMEOUT"
INVALID_RESULT = "INVALID_RESULT"
UNKNOWN_VERDICT = "UNKNOWN_VERDICT"
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
        try:
            result = self.docker.exec(self.sidecar, command, timeout=self.timeout)
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
                "probe timed out after %ss" % self.timeout,
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
