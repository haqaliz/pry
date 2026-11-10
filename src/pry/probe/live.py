"""Scan a live URL read-only after proving ownership.

The P1 token is the authorization gate: it is validated before any probe or
request runs, and it is never written to the run directory.
"""

import secrets
from pathlib import Path

from pry.intake.snapshot import new_run_dir, utc_now, write_snapshot
from pry.own.target import normalize_target
from pry.own.tokens import TokenSigner
from pry.probe.idor import probe_idor
from pry.probe.results import ProbeResult
from pry.probe.scan import (
    SCAN_VERSION,
    ScanOutcome,
    finalize_results,
    validate_endpoints,
)
from pry.probe.sidecar import (
    probe_cors,
    probe_database,
    probe_errors,
    probe_headers,
    probe_secrets,
    probe_unauth,
)

LIVE_PREFIX = "live-"


def _snapshot(target, sandbox_id, created_at, proof_type):
    return {
        "version": SCAN_VERSION,
        "sandbox_id": sandbox_id,
        "created_at": created_at,
        "target": {
            "path": target.origin,
            "kind": "live",
            "url": target.origin,
            "ownership_proof": proof_type,
            "git_commit": None,
            "git_dirty": None,
            "tree_sha256": None,
        },
        "project": {
            "package_manager": None,
            "lockfile": None,
            "lockfile_sha256": None,
            "image": None,
            "image_digest": None,
            "install": None,
            "build": None,
            "start": None,
            "port": None,
        },
        "sandbox": {
            "network": "live",
            "container_id": None,
            "workspace": None,
            "internal_url": target.origin,
        },
        "result": {"status": "ready"},
    }


def _run_probes(origin, endpoints, idor_config=None):
    results = [
        ProbeResult(**probe_cors(origin)),
        ProbeResult(**probe_errors(origin)),
        ProbeResult(**probe_secrets(origin)),
        ProbeResult(**probe_database(origin)),
    ]
    results.extend(
        ProbeResult(**probe_unauth(origin, path)) for path in endpoints
    )
    if idor_config is not None:
        results.append(ProbeResult(**probe_idor(origin, idor_config)))
    return results


def scan_live(
    url, token, *, endpoints=None, out=None, idor_config=None, headers=False
):
    """Prove ownership of ``url``, run the read-only probes, finalize."""
    target = normalize_target(url)
    proof = TokenSigner().validate(token, target)
    endpoints = validate_endpoints(endpoints)

    sandbox_id = LIVE_PREFIX + secrets.token_hex(6)
    if out is None:
        run_dir = new_run_dir(Path.home() / ".pry" / "runs" / sandbox_id)
    else:
        run_dir = new_run_dir(out)
    snapshot = _snapshot(target, sandbox_id, utc_now(), proof.proof_type)
    write_snapshot(run_dir, snapshot)

    results = _run_probes(target.origin, endpoints, idor_config)
    observations = [probe_headers(target.origin)] if headers else []
    results, summary, results_path, corpus_error = finalize_results(
        run_dir, snapshot, results, observations
    )
    return ScanOutcome(
        snapshot=snapshot,
        results=results,
        results_path=results_path,
        summary=summary,
        corpus_error=corpus_error,
        observations=observations,
    )
