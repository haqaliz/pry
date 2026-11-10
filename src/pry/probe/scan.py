"""Scan a local repository in the sandbox and write results.json."""

import json
import os
import secrets
import tempfile
from dataclasses import asdict, dataclass, field, replace
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
from pry.probe.ssrf import (
    SSRF_PROBE_FAILED,
    new_nonce,
    parse_ssrf_result,
    ssrf_failure,
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
SSRF_PROBE_PATH = "/pry/ssrf_probe.py"
SSRF_CALLBACK_BASE = "http://pry-callback:9000"
SSRF_EXEC_TIMEOUT = 30


@dataclass(frozen=True)
class ScanOutcome:
    snapshot: dict
    results: list
    results_path: Path
    summary: dict
    corpus_error: Optional[str] = None
    observations: list = field(default_factory=list)


def sidecar_script_path() -> Path:
    return Path(__file__).with_name("sidecar.py")


def callback_source_dir() -> Path:
    return Path(__file__).with_name("callback_server.py").parent


def _write_idor_config(config) -> str:
    """Write the declared pair to a 0600 temp file for the read-only mount."""
    payload = {
        "identity_a": {"headers": dict(config.headers_a)},
        "identity_b": {"headers": dict(config.headers_b)},
        "object_a": config.object_a,
        "object_b": config.object_b,
    }
    handle, path = tempfile.mkstemp(prefix="pry-idor-", suffix=".json")
    try:
        os.fchmod(handle, 0o600)
        with os.fdopen(handle, "w", encoding="utf-8") as stream:
            json.dump(payload, stream)
    except BaseException:
        try:
            os.close(handle)
        except OSError:
            pass
        try:
            os.unlink(path)
        except OSError:
            pass
        raise
    return path


def _probe_payload(result):
    if result.timed_out:
        raise ProbeError(
            SSRF_PROBE_FAILED,
            "ssrf probe timed out after %ss" % SSRF_EXEC_TIMEOUT,
        )
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).decode(
            "utf-8", "replace"
        ).strip()
        raise ProbeError(
            SSRF_PROBE_FAILED, detail[:500] or "exit code %d" % result.returncode
        )
    try:
        return json.loads(result.stdout.decode("utf-8", "replace"))
    except ValueError:
        return None


def _run_ssrf(runner, network, sandbox_id, app_base, config):
    """Run the probe inside the callback sidecar and always remove it."""
    callback = "pry-callback-" + sandbox_id
    try:
        runner.start_callback_sidecar(
            network, callback, callback_source_dir()
        )
        nonce = new_nonce()
        result = runner.exec(
            callback,
            [
                "python",
                SSRF_PROBE_PATH,
                app_base,
                config.endpoint,
                config.parameter,
                nonce,
                SSRF_CALLBACK_BASE,
            ],
            timeout=SSRF_EXEC_TIMEOUT,
        )
        return parse_ssrf_result(_probe_payload(result), config)
    except Exception as exc:
        message = getattr(exc, "message", None) or str(exc) or "unknown error"
        return ssrf_failure(
            SSRF_PROBE_FAILED,
            "ssrf probe failed: %s" % message[:500],
            app_base,
            config,
        )
    finally:
        runner.remove(callback)


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


def finalize_results(run_dir, snapshot, results, observations=None):
    """Sign, summarize, write results.json, and bank the corpus for one run.

    Shared by the local and live paths so they cannot drift. Observations are
    hardening evidence: they are written beside the results, never signed.
    """
    results = _sign_exposed(run_dir, snapshot, results)
    summary = summarize(results)
    scan_result = ScanResult(
        version=SCAN_VERSION,
        target={
            "sandbox_id": snapshot["sandbox_id"],
            "path": snapshot["target"]["path"],
            "kind": snapshot["target"]["kind"],
        },
        results=results,
        summary=summary,
        created_at=utc_now(),
        observations=list(observations or []),
    )
    results_path = write_results(run_dir, asdict(scan_result))
    corpus_error = None
    try:
        append_findings(
            _corpus_records(snapshot, results, scan_result.created_at)
        )
    except ReportError as exc:
        corpus_error = str(exc)
    return results, summary, results_path, corpus_error


def scan_local(
    path,
    *,
    out=None,
    timeout=None,
    port=None,
    docker=None,
    endpoints=None,
    ssrf_config=None,
    rate_limit_config=None,
    idor_config=None,
):
    _validated_path(path)
    endpoints = validate_endpoints(endpoints)
    runner = docker if docker is not None else DockerRunner()
    network = "pry-net-" + secrets.token_hex(6)
    results = []
    observations = []
    corpus_error = None
    config_path = None

    def on_ready(handle: SandboxHandle) -> None:
        sidecar = "pry-probe-" + handle.sandbox_id
        app_base = "http://app:%d" % handle.port
        failure = None
        try:
            if config_path is None:
                runner.start_sidecar(network, sidecar, sidecar_script_path())
            else:
                runner.start_sidecar(
                    network,
                    sidecar,
                    sidecar_script_path(),
                    config_path=config_path,
                )
            client = ProbeClient(runner, sidecar, app_base)
            results.extend(client.run_all())
            for endpoint in endpoints:
                results.append(client.run("unauth", endpoint=endpoint))
            if ssrf_config is not None:
                results.append(
                    _run_ssrf(
                        runner,
                        network,
                        handle.sandbox_id,
                        app_base,
                        ssrf_config,
                    )
                )
            if rate_limit_config is not None:
                observations.append(
                    client.run_rate_limit(
                        rate_limit_config.endpoint, rate_limit_config.count
                    )
                )
            if idor_config is not None:
                results.append(client.run_idor())
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
        if idor_config is not None:
            config_path = _write_idor_config(idor_config)
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
        results, summary, results_path, corpus_error = finalize_results(
            run_dir, intake_result.snapshot, results, observations
        )
    except BaseException as exc:
        failure = exc
        raise
    finally:
        if config_path is not None:
            try:
                os.unlink(config_path)
            except OSError:
                pass
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
        observations=observations,
    )
