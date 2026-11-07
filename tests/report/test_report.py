"""Report load/verify/render tests (AT2-AT6)."""

import json
import stat

import pytest

from pry.probe.results import EXPOSED, NOT_REPRODUCED, UNVERIFIED
from pry.proof import ProofSigner, build_bundle, write_bundle
from pry.report.corpus import (
    REPORT_FAILED,
    REPORT_MALFORMED,
    REPORT_MISSING,
    ReportError,
)
from pry.report.report import (
    _target_basename,
    load_run,
    render_html,
    write_report,
)

SANDBOX_ID = "pry-0123456789ab"
COMMIT = "a" * 40
CREATED_AT = "2026-11-08T01:02:03Z"
TARGET = {
    "path": "/repos/acme-app",
    "kind": "node",
    "git_commit": COMMIT,
    "git_dirty": True,
    "tree_sha256": "b" * 64,
}


@pytest.fixture(autouse=True)
def proof_key(tmp_path, monkeypatch):
    path = tmp_path / "proof.key"
    monkeypatch.setenv("PRY_PROOF_KEY", str(path))
    return path


def _snapshot():
    return {
        "version": 1,
        "sandbox_id": SANDBOX_ID,
        "created_at": "2026-11-08T00:00:00Z",
        "target": dict(TARGET),
        "project": {
            "image": "python:3.9-slim",
            "image_digest": "sha256:" + "c" * 64,
            "port": 8000,
        },
        "sandbox": {},
        "result": {},
    }


def _entry(
    probe,
    verdict,
    *,
    proof=None,
    evidence=None,
    body="ok",
    request_headers=None,
    response_headers=None,
):
    return {
        "probe": probe,
        "verdict": verdict,
        "cause": None,
        "evidence": evidence if evidence is not None else "%s checked" % probe,
        "request": {
            "method": "GET",
            "url": "http://app:8000/",
            "headers": request_headers
            if request_headers is not None
            else {"user-agent": "pry/0.1"},
        },
        "response": {
            "status": 200,
            "headers": response_headers
            if response_headers is not None
            else {"content-type": "text/html"},
            "body": body,
        },
        "proof": proof,
    }


def _write_results(run_dir, entries):
    path = run_dir / "results.json"
    path.write_text(
        json.dumps(
            {
                "version": 1,
                "target": {
                    "sandbox_id": SANDBOX_ID,
                    "path": TARGET["path"],
                    "kind": TARGET["kind"],
                },
                "results": entries,
                "summary": {
                    EXPOSED: sum(1 for e in entries if e["verdict"] == EXPOSED),
                    NOT_REPRODUCED: sum(
                        1 for e in entries if e["verdict"] == NOT_REPRODUCED
                    ),
                    UNVERIFIED: sum(
                        1 for e in entries if e["verdict"] == UNVERIFIED
                    ),
                },
                "created_at": CREATED_AT,
            },
            indent=2,
        ),
        encoding="utf-8",
    )


def _write_run(tmp_path, entries, snapshot=None):
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    (run_dir / "snapshot.json").write_text(
        json.dumps(snapshot if snapshot is not None else _snapshot(), indent=2),
        encoding="utf-8",
    )
    _write_results(run_dir, entries)
    return run_dir


def _sign(run_dir, finding):
    signer = ProofSigner()
    bundle = build_bundle(
        {"sandbox_id": SANDBOX_ID, "path": TARGET["path"], "kind": TARGET["kind"]},
        finding,
        signer=signer,
        created_at=CREATED_AT,
    )
    return write_bundle(run_dir, bundle), signer.fingerprint


def _signed_run(tmp_path, **overrides):
    entries = [
        _entry("cors", EXPOSED, **overrides),
        _entry("errors", NOT_REPRODUCED),
        _entry("secrets", UNVERIFIED),
    ]
    run_dir = _write_run(tmp_path, entries)
    proof, fingerprint = _sign(run_dir, entries[0])
    entries[0]["proof"] = str(proof)
    _write_results(run_dir, entries)
    return run_dir, fingerprint


def test_load_run_reads_target_counts_and_findings(tmp_path):
    run_dir, fingerprint = _signed_run(tmp_path)

    report = load_run(run_dir)

    assert report.snapshot_id == SANDBOX_ID
    assert report.target["path"] == TARGET["path"]
    assert report.target["kind"] == "node"
    assert report.created_at == CREATED_AT
    assert report.counts == {EXPOSED: 1, NOT_REPRODUCED: 1, UNVERIFIED: 1}
    assert [finding.probe for finding in report.findings] == [
        "cors",
        "errors",
        "secrets",
    ]
    exposed = report.findings[0]
    assert exposed.proof_status == "VALID"
    assert exposed.fingerprint == fingerprint
    assert exposed.proof_error is None
    assert report.findings[1].proof_status is None
    assert report.findings[1].fingerprint is None


def test_load_run_resolves_a_relative_proof_against_the_run_dir(tmp_path):
    run_dir, _ = _signed_run(tmp_path)
    data = json.loads((run_dir / "results.json").read_text(encoding="utf-8"))
    data["results"][0]["proof"] = "proofs/" + "a" * 64 + ".json"
    (run_dir / "results.json").write_text(json.dumps(data), encoding="utf-8")

    assert load_run(run_dir).findings[0].proof_status == "INVALID"

    proof = next((run_dir / "proofs").glob("*.json"))
    data["results"][0]["proof"] = str(proof.relative_to(run_dir))
    (run_dir / "results.json").write_text(json.dumps(data), encoding="utf-8")

    assert load_run(run_dir).findings[0].proof_status == "VALID"


def test_load_run_resolves_a_relative_proof_against_the_cwd(tmp_path, monkeypatch):
    run_dir = _write_run(tmp_path, [_entry("cors", EXPOSED)])
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    proof, _ = _sign(elsewhere, _entry("cors", EXPOSED))
    data = json.loads((run_dir / "results.json").read_text(encoding="utf-8"))
    data["results"][0]["proof"] = str(proof.relative_to(elsewhere))
    (run_dir / "results.json").write_text(json.dumps(data), encoding="utf-8")
    monkeypatch.chdir(elsewhere)

    assert load_run(run_dir).findings[0].proof_status == "VALID"


def test_a_tampered_proof_is_invalid_with_a_reason(tmp_path):
    run_dir, _ = _signed_run(tmp_path)
    proof = next((run_dir / "proofs").glob("*.json"))
    bundle = json.loads(proof.read_text(encoding="utf-8"))
    bundle["payload"]["finding"]["evidence"] = "tampered"
    proof.write_text(json.dumps(bundle), encoding="utf-8")

    finding = load_run(run_dir).findings[0]

    assert finding.proof_status == "INVALID"
    assert finding.fingerprint is None
    assert finding.proof_error


def test_an_exposed_finding_without_a_proof_is_unsigned(tmp_path):
    run_dir = _write_run(tmp_path, [_entry("cors", EXPOSED)])

    finding = load_run(run_dir).findings[0]

    assert finding.proof_status == "UNSIGNED"
    assert finding.fingerprint is None
    assert finding.proof is None
    assert finding.proof_error


def test_a_missing_proof_file_is_invalid(tmp_path):
    entry = _entry("cors", EXPOSED, proof="proofs/missing.json")
    run_dir = _write_run(tmp_path, [entry])

    finding = load_run(run_dir).findings[0]

    assert finding.proof_status == "INVALID"
    assert finding.fingerprint is None
    assert "cannot read" in finding.proof_error


@pytest.mark.parametrize("name", ["snapshot.json", "results.json"])
def test_missing_run_files_raise_report_missing(tmp_path, name):
    run_dir = _write_run(tmp_path, [_entry("cors", NOT_REPRODUCED)])
    (run_dir / name).unlink()

    with pytest.raises(ReportError) as exc:
        load_run(run_dir)

    assert exc.value.cause == REPORT_MISSING


def test_a_missing_run_dir_raises_report_missing(tmp_path):
    with pytest.raises(ReportError) as exc:
        load_run(tmp_path / "missing")

    assert exc.value.cause == REPORT_MISSING


@pytest.mark.parametrize("name", ["snapshot.json", "results.json"])
def test_invalid_json_raises_report_malformed(tmp_path, name):
    run_dir = _write_run(tmp_path, [_entry("cors", NOT_REPRODUCED)])
    (run_dir / name).write_text("{not json", encoding="utf-8")

    with pytest.raises(ReportError) as exc:
        load_run(run_dir)

    assert exc.value.cause == REPORT_MALFORMED


def test_results_without_a_results_list_are_malformed(tmp_path):
    run_dir = _write_run(tmp_path, [_entry("cors", NOT_REPRODUCED)])
    (run_dir / "results.json").write_text(
        json.dumps({"version": 1, "results": "no"}), encoding="utf-8"
    )

    with pytest.raises(ReportError) as exc:
        load_run(run_dir)

    assert exc.value.cause == REPORT_MALFORMED


def test_a_snapshot_without_a_target_is_malformed(tmp_path):
    snapshot = _snapshot()
    del snapshot["target"]
    run_dir = _write_run(tmp_path, [_entry("cors", NOT_REPRODUCED)], snapshot)

    with pytest.raises(ReportError) as exc:
        load_run(run_dir)

    assert exc.value.cause == REPORT_MALFORMED


def test_render_html_contains_target_counts_findings_and_caveats(tmp_path):
    run_dir, fingerprint = _signed_run(tmp_path)

    html = render_html(load_run(run_dir))

    assert html.startswith("<!DOCTYPE html>")
    for value in (
        "acme-app",
        "node",
        COMMIT,
        "Dirty",
        SANDBOX_ID,
        "EXPOSED",
        "NOT_REPRODUCED",
        "UNVERIFIED",
        "cors",
        "GET",
        "http://app:8000/",
        "ok",
        fingerprint,
        "VALID",
        "not proof of absence",
        "Deferred checks",
    ):
        assert value in html


def test_render_html_escapes_scripts_in_evidence_body_and_headers(tmp_path):
    payload = "<script>alert(1)</script>"
    entry = _entry(
        "cors",
        EXPOSED,
        evidence=payload,
        body=payload,
        request_headers={"x-request": "<script>alert(2)</script>"},
        response_headers={"x-response": "<script>alert(3)</script>"},
    )
    run_dir = _write_run(tmp_path, [entry])

    html = render_html(load_run(run_dir))

    assert "<script" not in html.lower()
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    assert "&lt;script&gt;alert(2)&lt;/script&gt;" in html
    assert "&lt;script&gt;alert(3)&lt;/script&gt;" in html


def test_render_html_is_self_contained_without_javascript_or_external_assets(
    tmp_path,
):
    run_dir, _ = _signed_run(tmp_path)

    html = render_html(load_run(run_dir))
    lowered = html.lower()

    assert "<script" not in lowered
    assert "<link" not in lowered
    assert "<img" not in lowered
    assert " src=" not in lowered
    assert " href=" not in lowered
    assert "<style>" in lowered


def test_a_safe_run_has_zero_exposed_and_no_fingerprints(tmp_path):
    entries = [
        _entry("cors", NOT_REPRODUCED),
        _entry("errors", NOT_REPRODUCED),
        _entry("secrets", UNVERIFIED),
    ]
    run_dir = _write_run(tmp_path, entries)

    report = load_run(run_dir)

    assert report.counts[EXPOSED] == 0
    assert all(
        finding.fingerprint is None and finding.proof_status is None
        for finding in report.findings
    )
    html = render_html(report)
    assert "SAFE" not in html
    assert "SECURE" not in html


def test_write_report_defaults_to_the_run_dir_and_is_0600(tmp_path):
    run_dir, _ = _signed_run(tmp_path)

    path = write_report(run_dir)

    assert path == run_dir / "report.html"
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert path.read_text(encoding="utf-8").startswith("<!DOCTYPE html>")
    assert not (run_dir / "report.html.tmp").exists()


def test_write_report_honors_an_out_path(tmp_path):
    run_dir, _ = _signed_run(tmp_path)
    out = tmp_path / "elsewhere" / "findings.html"

    path = write_report(run_dir, out=out)

    assert path == out
    assert stat.S_IMODE(out.stat().st_mode) == 0o600
    assert out.read_text(encoding="utf-8").startswith("<!DOCTYPE html>")


def test_write_report_failure_raises_report_failed(tmp_path):
    run_dir, _ = _signed_run(tmp_path)
    blocker = tmp_path / "blocker"
    blocker.write_text("not a directory", encoding="utf-8")

    with pytest.raises(ReportError) as exc:
        write_report(run_dir, out=blocker / "report.html")

    assert exc.value.cause == REPORT_FAILED


LIVE_URL = "https://app.example.com"
LIVE_SANDBOX_ID = "live-0123456789ab"


def _live_snapshot():
    return {
        "version": 1,
        "sandbox_id": LIVE_SANDBOX_ID,
        "created_at": "2026-11-08T00:00:00Z",
        "target": {
            "path": LIVE_URL,
            "kind": "live",
            "url": LIVE_URL,
            "ownership_proof": "dns_txt",
            "git_commit": None,
            "git_dirty": None,
            "tree_sha256": None,
        },
        "project": {},
        "sandbox": {"network": "live"},
        "result": {"status": "ready"},
    }


def _signed_live_run(tmp_path):
    entries = [
        _entry("cors", EXPOSED),
        _entry("errors", NOT_REPRODUCED),
        _entry("secrets", UNVERIFIED),
    ]
    run_dir = _write_run(tmp_path, entries, _live_snapshot())
    signer = ProofSigner()
    bundle = build_bundle(
        {
            "sandbox_id": LIVE_SANDBOX_ID,
            "path": LIVE_URL,
            "kind": "live",
            "url": LIVE_URL,
            "ownership_proof": "dns_txt",
        },
        entries[0],
        signer=signer,
        created_at=CREATED_AT,
    )
    proof = write_bundle(run_dir, bundle)
    entries[0]["proof"] = str(proof)
    _write_results(run_dir, entries)
    return run_dir, signer.fingerprint


def test_target_basename_handles_urls_and_local_paths():
    assert _target_basename("https://app.example.com/x") == "app.example.com"
    assert _target_basename("/repos/acme-app") == "acme-app"


def test_a_live_report_shows_the_host_url_and_ownership_proof(tmp_path):
    run_dir, fingerprint = _signed_live_run(tmp_path)

    report = load_run(run_dir)
    html = render_html(report)

    assert report.target["kind"] == "live"
    assert "app.example.com" in html
    assert LIVE_URL in html
    assert "Ownership proof" in html
    assert "dns_txt" in html
    assert fingerprint in html
    assert "VALID" in html
    assert str(tmp_path) not in html
    assert "Commit" not in html
    assert "Dirty" not in html


def test_a_local_report_keeps_the_commit_rows_without_live_fields(tmp_path):
    run_dir, _ = _signed_run(tmp_path)

    html = render_html(load_run(run_dir))

    assert "Commit" in html
    assert COMMIT in html
    assert "Ownership proof" not in html
    assert "<dt>URL</dt>" not in html
