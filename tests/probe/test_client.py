"""Host-side probe client tests (transport only).

Every test injects a fake docker; nothing here starts a container, runs the
real sidecar, or opens a socket.
"""

import json

import pytest

from pry.intake.docker import CommandResult
from pry.probe.client import (
    EXEC_FAILED,
    EXEC_TIMEOUT,
    INVALID_RESULT,
    PROBE_ORDER,
    RATE_LIMIT_TIMEOUT,
    UNKNOWN_VERDICT,
    ProbeClient,
)
from pry.probe.rate_limit import OBSERVED, THROTTLED
from pry.probe.results import EXPOSED, UNVERIFIED, ProbeResult

BASE = "http://app:3000"
SIDECAR = "pry-probe-pry-0123456789ab"


class FakeDocker:
    """Records exec calls and returns scripted results in order."""

    def __init__(self, results=None):
        self.calls = []
        self.results = list(results or [])

    def exec(self, container, command, timeout=10):
        self.calls.append((container, list(command), timeout))
        if self.results:
            result = self.results.pop(0)
            if isinstance(result, Exception):
                raise result
            return result
        return CommandResult(0, b"", b"", False)


def _payload(probe="cors", verdict=EXPOSED):
    return {
        "probe": probe,
        "verdict": verdict,
        "cause": None,
        "evidence": "reproduced",
        "request": {
            "method": "GET",
            "url": BASE + "/",
            "headers": {"Origin": "https://pry.invalid"},
        },
        "response": {
            "status": 200,
            "headers": {"Access-Control-Allow-Origin": "https://pry.invalid"},
            "body": "ok",
        },
    }


def _json(payload):
    return CommandResult(0, json.dumps(payload).encode("utf-8"), b"", False)


def test_run_calls_docker_exec_with_the_exact_argv():
    fake = FakeDocker([_json(_payload())])

    result = ProbeClient(fake, SIDECAR, BASE).run("cors")

    assert fake.calls == [(SIDECAR, ["python", "/pry/sidecar.py", "cors", BASE], 20)]
    assert result.verdict == EXPOSED


def test_a_custom_timeout_is_passed_to_exec():
    fake = FakeDocker([_json(_payload("errors"))])

    ProbeClient(fake, SIDECAR, BASE, timeout=7).run("errors")

    assert fake.calls[0][2] == 7


def test_valid_json_is_parsed_into_a_probe_result():
    payload = _payload()

    result = ProbeClient(FakeDocker([_json(payload)]), SIDECAR, BASE).run("cors")

    assert result == ProbeResult(**payload)
    assert result.request["headers"] == {"origin": "https://pry.invalid"}
    assert result.response["headers"] == {
        "access-control-allow-origin": "https://pry.invalid"
    }


@pytest.mark.parametrize(
    "command",
    [
        CommandResult(1, b"", b"sidecar exploded", False),
        CommandResult(125, b"", b"", False),
    ],
)
def test_nonzero_exit_is_unverified_with_a_cause(command):
    result = ProbeClient(FakeDocker([command]), SIDECAR, BASE).run("cors")

    assert result.probe == "cors"
    assert result.verdict == UNVERIFIED
    assert result.cause == EXEC_FAILED
    assert result.response is None
    assert result.evidence


def test_timeout_is_unverified_with_a_cause():
    fake = FakeDocker([CommandResult(-1, b"", b"", True)])

    result = ProbeClient(fake, SIDECAR, BASE).run("errors")

    assert result.verdict == UNVERIFIED
    assert result.cause == EXEC_TIMEOUT
    assert result.response is None


@pytest.mark.parametrize("stdout", [b"not json", b"", b"[1, 2]"])
def test_invalid_json_is_unverified_with_a_cause(stdout):
    fake = FakeDocker([CommandResult(0, stdout, b"", False)])

    result = ProbeClient(fake, SIDECAR, BASE).run("secrets")

    assert result.verdict == UNVERIFIED
    assert result.cause == INVALID_RESULT
    assert result.response is None


def test_a_result_without_every_field_is_unverified_with_a_cause():
    payload = _payload()
    del payload["response"]

    result = ProbeClient(FakeDocker([_json(payload)]), SIDECAR, BASE).run("cors")

    assert result.verdict == UNVERIFIED
    assert result.cause == INVALID_RESULT
    assert result.response is None


def test_an_unknown_verdict_is_unverified_with_a_cause():
    payload = _payload(verdict="SAFE")

    result = ProbeClient(FakeDocker([_json(payload)]), SIDECAR, BASE).run("cors")

    assert result.verdict == UNVERIFIED
    assert result.cause == UNKNOWN_VERDICT
    assert result.response is None


def test_a_docker_exec_exception_is_unverified_and_does_not_escape():
    fake = FakeDocker([RuntimeError("docker exec exploded")])

    result = ProbeClient(fake, SIDECAR, BASE).run("cors")

    assert result.verdict == UNVERIFIED
    assert result.cause == EXEC_FAILED
    assert "docker exec exploded" in result.evidence


def test_run_all_runs_cors_errors_and_secrets_in_order():
    fake = FakeDocker(
        [
            _json(_payload("cors")),
            _json(_payload("errors")),
            _json(_payload("secrets")),
        ]
    )

    results = ProbeClient(fake, SIDECAR, BASE).run_all()

    assert list(PROBE_ORDER) == ["cors", "errors", "secrets"]
    assert [call[1][2] for call in fake.calls] == ["cors", "errors", "secrets"]
    assert [result.probe for result in results] == ["cors", "errors", "secrets"]
    assert len(fake.calls) == 3


def test_run_unauth_appends_the_declared_path():
    fake = FakeDocker([_json(_payload("unauth"))])

    result = ProbeClient(fake, SIDECAR, BASE).run(
        "unauth", endpoint="/api/users"
    )

    assert fake.calls == [
        (
            SIDECAR,
            ["python", "/pry/sidecar.py", "unauth", BASE, "/api/users"],
            20,
        )
    ]
    assert result.probe == "unauth"


def test_run_default_probes_ignore_an_endpoint_argument():
    fake = FakeDocker([_json(_payload("errors"))])

    ProbeClient(fake, SIDECAR, BASE).run("errors", endpoint="/api/users")

    assert fake.calls[0][1] == ["python", "/pry/sidecar.py", "errors", BASE]


def test_an_unauth_exec_failure_is_unverified_with_a_cause():
    fake = FakeDocker([CommandResult(2, b"", b"usage: sidecar.py", False)])

    result = ProbeClient(fake, SIDECAR, BASE).run(
        "unauth", endpoint="/api/users"
    )

    assert result.probe == "unauth"
    assert result.verdict == UNVERIFIED
    assert result.cause == EXEC_FAILED
    assert result.response is None
    assert "usage" in result.evidence


def test_an_unauth_timeout_is_unverified_with_a_cause():
    fake = FakeDocker([CommandResult(-1, b"", b"", True)])

    result = ProbeClient(fake, SIDECAR, BASE).run(
        "unauth", endpoint="/api/users"
    )

    assert result.verdict == UNVERIFIED
    assert result.cause == EXEC_TIMEOUT
    assert result.response is None


def test_the_sidecars_invalid_endpoint_cause_is_carried_through():
    payload = _payload("unauth", UNVERIFIED)
    payload["cause"] = "INVALID_ENDPOINT"
    payload["response"] = None
    fake = FakeDocker([_json(payload)])

    result = ProbeClient(fake, SIDECAR, BASE).run(
        "unauth", endpoint="http://evil.invalid"
    )

    assert result.verdict == UNVERIFIED
    assert result.cause == "INVALID_ENDPOINT"
    assert result.response is None


RATE_PATH = "/api/ping"


def _observation(status=OBSERVED, count=10):
    return {
        "probe": "rate_limit",
        "status": status,
        "evidence": "10 requests accepted without throttling "
        "(hardening observation)",
        "request": {
            "method": "GET",
            "url": BASE + RATE_PATH,
            "headers": {"User-Agent": "pry/0.1"},
        },
        "response": {"status": 200, "headers": {}, "body": "ok"},
        "count": count,
        "statuses": [200] * count,
    }


def test_run_rate_limit_execs_the_sidecar_with_the_count():
    fake = FakeDocker([_json(_observation())])

    result = ProbeClient(fake, SIDECAR, BASE).run_rate_limit(RATE_PATH, 10)

    assert fake.calls == [
        (
            SIDECAR,
            [
                "python",
                "/pry/sidecar.py",
                "rate_limit",
                BASE,
                RATE_PATH,
                "10",
            ],
            RATE_LIMIT_TIMEOUT,
        )
    ]
    assert RATE_LIMIT_TIMEOUT == 120
    assert result["probe"] == "rate_limit"
    assert result["status"] == OBSERVED
    assert result["count"] == 10
    assert result["statuses"] == [200] * 10
    assert result["request"]["headers"] == {"user-agent": "pry/0.1"}


def test_run_rate_limit_keeps_a_throttled_observation():
    payload = _observation(THROTTLED, 4)
    payload["statuses"] = [200, 200, 200, 429]
    payload["evidence"] = "throttled at request 4/10: status 429"
    fake = FakeDocker([_json(payload)])

    result = ProbeClient(fake, SIDECAR, BASE).run_rate_limit(RATE_PATH, 10)

    assert result["status"] == THROTTLED
    assert result["count"] == 4
    assert result["statuses"] == [200, 200, 200, 429]


@pytest.mark.parametrize(
    "command",
    [
        CommandResult(1, b"", b"sidecar exploded", False),
        CommandResult(125, b"", b"", False),
    ],
)
def test_a_rate_limit_nonzero_exit_is_an_unverified_observation(command):
    result = ProbeClient(FakeDocker([command]), SIDECAR, BASE).run_rate_limit(
        RATE_PATH, 10
    )

    assert result["probe"] == "rate_limit"
    assert result["status"] == UNVERIFIED
    assert result["count"] == 0
    assert result["statuses"] == []
    assert result["response"] is None
    assert EXEC_FAILED in result["evidence"]


def test_a_rate_limit_timeout_is_an_unverified_observation():
    fake = FakeDocker([CommandResult(-1, b"", b"", True)])

    result = ProbeClient(fake, SIDECAR, BASE).run_rate_limit(RATE_PATH, 10)

    assert result["status"] == UNVERIFIED
    assert EXEC_TIMEOUT in result["evidence"]
    assert result["response"] is None


@pytest.mark.parametrize("stdout", [b"not json", b"", b"[1, 2]"])
def test_invalid_rate_limit_json_is_an_unverified_observation(stdout):
    fake = FakeDocker([CommandResult(0, stdout, b"", False)])

    result = ProbeClient(fake, SIDECAR, BASE).run_rate_limit(RATE_PATH, 10)

    assert result["status"] == UNVERIFIED
    assert INVALID_RESULT in result["evidence"]
    assert result["response"] is None


def test_a_rate_limit_docker_exception_is_unverified_and_does_not_escape():
    fake = FakeDocker([RuntimeError("docker exec exploded")])

    result = ProbeClient(fake, SIDECAR, BASE).run_rate_limit(RATE_PATH, 10)

    assert result["status"] == UNVERIFIED
    assert EXEC_FAILED in result["evidence"]
    assert "docker exec exploded" in result["evidence"]


def test_a_rate_limit_payload_that_tries_to_carry_a_verdict_is_unverified():
    payload = dict(_observation(), verdict=EXPOSED)
    fake = FakeDocker([_json(payload)])

    result = ProbeClient(fake, SIDECAR, BASE).run_rate_limit(RATE_PATH, 10)

    assert result["status"] == UNVERIFIED
    assert "RATE_LIMIT_PROBE_INVALID" in result["evidence"]
    assert "verdict" not in result


IDOR_CONFIG_PATH = "/pry-config/idor.json"


def _idor_payload(verdict=EXPOSED, cause=None):
    return {
        "probe": "idor",
        "verdict": verdict,
        "cause": cause,
        "evidence": "control A passed; control B passed; cross checked",
        "request": {
            "method": "GET",
            "url": BASE + "/api/orders/2",
            "headers": {"cookie": "[redacted]"},
        },
        "response": {
            "status": 200,
            "headers": {"set-cookie": "[redacted]"},
            "body": '{"id": 2}',
        },
    }


def test_run_idor_execs_the_sidecar_with_the_mounted_config():
    fake = FakeDocker([_json(_idor_payload())])

    result = ProbeClient(fake, SIDECAR, BASE).run_idor()

    assert fake.calls == [
        (
            SIDECAR,
            [
                "python",
                "/pry/sidecar.py",
                "idor",
                BASE,
                IDOR_CONFIG_PATH,
            ],
            20,
        )
    ]
    assert result == ProbeResult(**_idor_payload())
    assert result.probe == "idor"
    assert result.verdict == EXPOSED


def test_run_idor_carries_the_sidecars_unverified_cause():
    payload = _idor_payload(UNVERIFIED, "IDOR_CONTROL_FAILED")
    payload["response"] = None
    fake = FakeDocker([_json(payload)])

    result = ProbeClient(fake, SIDECAR, BASE).run_idor()

    assert result.verdict == UNVERIFIED
    assert result.cause == "IDOR_CONTROL_FAILED"
    assert result.response is None


@pytest.mark.parametrize(
    "command",
    [
        CommandResult(1, b"", b"sidecar exploded", False),
        CommandResult(125, b"", b"", False),
        CommandResult(-1, b"", b"", True),
    ],
)
def test_a_run_idor_exec_failure_or_timeout_is_unverified(command):
    result = ProbeClient(FakeDocker([command]), SIDECAR, BASE).run_idor()

    assert result.probe == "idor"
    assert result.verdict == UNVERIFIED
    assert result.response is None
    assert result.cause in (EXEC_FAILED, EXEC_TIMEOUT)


def test_a_run_idor_docker_exception_is_unverified_and_does_not_escape():
    fake = FakeDocker([RuntimeError("docker exec exploded")])

    result = ProbeClient(fake, SIDECAR, BASE).run_idor()

    assert result.verdict == UNVERIFIED
    assert result.cause == EXEC_FAILED
    assert "docker exec exploded" in result.evidence


@pytest.mark.parametrize("stdout", [b"not json", b"", b"[1, 2]"])
def test_invalid_idor_json_is_unverified_with_a_cause(stdout):
    fake = FakeDocker([CommandResult(0, stdout, b"", False)])

    result = ProbeClient(fake, SIDECAR, BASE).run_idor()

    assert result.verdict == UNVERIFIED
    assert result.cause == INVALID_RESULT
    assert result.response is None


def test_an_unknown_idor_verdict_is_unverified_with_a_cause():
    payload = _idor_payload(verdict="SAFE")
    fake = FakeDocker([_json(payload)])

    result = ProbeClient(fake, SIDECAR, BASE).run_idor()

    assert result.verdict == UNVERIFIED
    assert result.cause == UNKNOWN_VERDICT
    assert result.response is None
