"""Scan a local repository in the sandbox and write results.json."""

import secrets
from dataclasses import asdict, dataclass, replace
from pathlib import Path
from typing import Optional

from pry.intake import SandboxHandle, intake
from pry.intake.docker import DockerRunner
from pry.intake.errors import REPO_NOT_FOUND, IntakeError
from pry.intake.snapshot import utc_now
from pry.probe.client import ProbeClient
from pry.probe.results import (
    EXPOSED,
    ProbeError,
    ProbeResult,
    ScanResult,
    summarize,
    write_results,
)
from pry.proof import (
    PROOF_FAILED,
    ProofError,
    ProofSigner,
    build_bundle,
    load_bundle,
    verify_bundle,
    write_bundle,
)
from pry.report.corpus import ReportError, append_findings

SCAN_VERSION = 1
ENDPOINT_LIMIT = 2048
INVALID_ENDPOINT = "INVALID_ENDPOINT"


@dataclass(frozen=True)
class ScanOutcome:
    snapshot: dict
    results: list
    results_path: Path
    summary: dict
    corpus_error: Optional[str] = None


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


def _proof_target(snapshot: dict) -> dict:
    target = snapshot["target"]
    project = snapshot["project"]
    return {
        "sandbox_id": snapshot["sandbox_id"],
        "path": target["path"],
        "kind": target["kind"],
        "git_commit": target.get("git_commit"),
        "git_dirty": target.get("git_dirty"),
        "tree_sha256": target.get("tree_sha256"),
        "image": project.get("image"),
        "image_digest": project.get("image_digest"),
        "port": project.get("port"),
    }


def _finding(result: ProbeResult) -> dict:
    return {
        "probe": result.probe,
        "verdict": result.verdict,
        "cause": result.cause,
        "evidence": result.evidence,
        "request": result.request,
        "response": result.response,
    }


def _fingerprint(proof):
    if not proof:
        return None
    try:
        _payload, fingerprint = verify_bundle(load_bundle(proof))
    except ProofError:
        return None
    return fingerprint


def _corpus_records(snapshot, results, created_at):
    target = snapshot["target"]
    return [
        {
            "created_at": created_at,
            "sandbox_id": snapshot["sandbox_id"],
            "target": target["path"],
            "kind": target["kind"],
            "probe": result.probe,
            "verdict": result.verdict,
            "cause": result.cause,
            "proof": result.proof,
            "fingerprint": _fingerprint(result.proof),
        }
        for result in results
    ]


def _sign_exposed(run_dir, snapshot, results):
    """Write one bundle per EXPOSED result and attach its path."""
    if not any(result.verdict == EXPOSED for result in results):
        return list(results)
    try:
        signer = ProofSigner()
        target = _proof_target(snapshot)
        signed = []
        for result in results:
            if result.verdict != EXPOSED:
                signed.append(result)
                continue
            bundle = build_bundle(target, _finding(result), signer=signer)
            path = write_bundle(run_dir, bundle)
            signed.append(replace(result, proof=str(path)))
        return signed
    except ProofError as exc:
        raise ProofError(
            PROOF_FAILED, "cannot sign findings: %s" % exc
        ) from exc


def scan_local(
    path, *, out=None, timeout=None, port=None, docker=None, endpoints=None
):
    _validated_path(path)
    endpoints = validate_endpoints(endpoints)
    runner = docker if docker is not None else DockerRunner()
    network = "pry-net-" + secrets.token_hex(6)
    results = []
    corpus_error = None

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
        run_dir = Path(intake_result.snapshot_path).parent
        results = _sign_exposed(run_dir, intake_result.snapshot, results)
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
        results_path = write_results(run_dir, asdict(scan_result))
        try:
            append_findings(
                _corpus_records(
                    intake_result.snapshot, results, scan_result.created_at
                )
            )
        except ReportError as exc:
            corpus_error = str(exc)
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
        corpus_error=corpus_error,
    )
