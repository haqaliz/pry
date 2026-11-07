"""Scan a local repository in the sandbox and write results.json."""

import secrets
from dataclasses import asdict, dataclass
from pathlib import Path

from pry.intake import SandboxHandle, intake
from pry.intake.docker import DockerRunner
from pry.intake.errors import REPO_NOT_FOUND, IntakeError
from pry.intake.snapshot import utc_now
from pry.probe.client import ProbeClient
from pry.probe.results import (
    ProbeError,
    ScanResult,
    summarize,
    write_results,
)

SCAN_VERSION = 1
ENDPOINT_LIMIT = 2048
INVALID_ENDPOINT = "INVALID_ENDPOINT"


@dataclass(frozen=True)
class ScanOutcome:
    snapshot: dict
    results: list
    results_path: Path
    summary: dict


def sidecar_script_path() -> Path:
    return Path(__file__).with_name("sidecar.py")


def _validated_path(path) -> Path:
    original = Path(path).expanduser()
    if not original.is_dir():
        raise IntakeError(REPO_NOT_FOUND, "not a directory: %s" % path)
    return original


def _is_endpoint_path(path) -> bool:
    if not isinstance(path, str) or not path or len(path) > ENDPOINT_LIMIT:
        return False
    if not path.startswith("/") or path.startswith("//") or "://" in path:
        return False
    return not any(
        char.isspace() or ord(char) < 32 or ord(char) == 127 for char in path
    )


def validate_endpoints(endpoints) -> list:
    """Return the declared paths unchanged, or fail before any Docker work."""
    endpoints = list(endpoints or ())
    for path in endpoints:
        if not _is_endpoint_path(path):
            raise ProbeError(
                INVALID_ENDPOINT,
                "invalid endpoint path %r: expected a path starting with '/', "
                "no '://', no leading '//', no whitespace or control "
                "characters, and at most %d characters"
                % (path, ENDPOINT_LIMIT),
            )
    return endpoints


def scan_local(
    path, *, out=None, timeout=None, port=None, docker=None, endpoints=None
):
    _validated_path(path)
    endpoints = validate_endpoints(endpoints)
    runner = docker if docker is not None else DockerRunner()
    network = "pry-net-" + secrets.token_hex(6)
    results = []

    def on_ready(handle: SandboxHandle) -> None:
        sidecar = "pry-probe-" + handle.sandbox_id
        failure = None
        try:
            runner.start_sidecar(network, sidecar, sidecar_script_path())
            client = ProbeClient(
                runner, sidecar, "http://app:%d" % handle.port
            )
            results.extend(client.run_all())
            for endpoint in endpoints:
                results.append(client.run("unauth", endpoint=endpoint))
        except BaseException as exc:
            failure = exc
            raise
        finally:
            try:
                runner.remove(sidecar)
            except Exception:
                if failure is None:
                    raise

    runner.create_network(network)
    failure = None
    try:
        intake_result = intake(
            path,
            out=out,
            port=port,
            timeout=timeout,
            docker=runner,
            network=network,
            on_ready=on_ready,
        )
        summary = summarize(results)
        scan_result = ScanResult(
            version=SCAN_VERSION,
            target={
                "sandbox_id": intake_result.snapshot["sandbox_id"],
                "path": intake_result.snapshot["target"]["path"],
                "kind": intake_result.snapshot["target"]["kind"],
            },
            results=results,
            summary=summary,
            created_at=utc_now(),
        )
        results_path = write_results(
            Path(intake_result.snapshot_path).parent, asdict(scan_result)
        )
    except BaseException as exc:
        failure = exc
        raise
    finally:
        try:
            runner.remove_network(network)
        except Exception:
            if failure is None:
                raise

    return ScanOutcome(
        snapshot=intake_result.snapshot,
        results=results,
        results_path=results_path,
        summary=summary,
    )
