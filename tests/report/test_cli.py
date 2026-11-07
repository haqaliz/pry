"""CLI report and scan integration tests (AT7-AT9)."""

import json
import stat
from dataclasses import asdict

import pytest

from pry.cli import main
from pry.probe.results import (
    EXPOSED,
    NOT_REPRODUCED,
    UNVERIFIED,
    ProbeResult,
    ScanResult,
    summarize,
    write_results,
)
from pry.probe.scan import ScanOutcome
from pry.report.corpus import REPORT_FAILED, ReportError

SANDBOX_ID = "pry-abc123"
CREATED_AT = "2026-11-08T00:00:00Z"
PROBES = ("cors", "errors", "secrets")


@pytest.fixture
def repo(tmp_path):
    path = tmp_path / "repo"
    path.mkdir()
    return path


def _probe_result(probe, verdict=NOT_REPRODUCED):
    return ProbeResult(
        probe=probe,
        verdict=verdict,
        cause=None,
        evidence="%s checked" % probe,
        request={
            "method": "GET",
            "url": "http://app:8000/",
            "headers": {"user-agent": "pry/0.1"},
        },
        response={"status": 200, "headers": {}, "body": "ok"},
    )


def _run_dir(tmp_path, verdicts=(NOT_REPRODUCED,) * 3):
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    snapshot = {
        "version": 1,
        "sandbox_id": SANDBOX_ID,
        "created_at": CREATED_AT,
        "target": {
            "path": "/repo",
            "kind": "static",
            "git_commit": "a" * 40,
            "git_dirty": False,
            "tree_sha256": "b" * 64,
        },
        "project": {},
        "sandbox": {},
        "result": {},
    }
    (run_dir / "snapshot.json").write_text(
        json.dumps(snapshot), encoding="utf-8"
    )
    results = [
        _probe_result(probe, verdict)
        for probe, verdict in zip(PROBES, verdicts)
    ]
    write_results(
        run_dir,
        asdict(
            ScanResult(
                version=1,
                target={
                    "sandbox_id": SANDBOX_ID,
                    "path": "/repo",
                    "kind": "static",
                },
                results=results,
                summary=summarize(results),
                created_at=CREATED_AT,
            )
        ),
    )
    return run_dir, results


def _outcome(run_dir, results, corpus_error=None):
    return ScanOutcome(
        snapshot={
            "sandbox_id": SANDBOX_ID,
            "target": {"path": "/repo", "kind": "static"},
        },
        results=results,
        results_path=run_dir / "results.json",
        summary=summarize(results),
        corpus_error=corpus_error,
    )


class FakeScanLocal:
    """Stand-in for pry.cli.scan_local; never touches Docker."""

    def __init__(self, outcome):
        self.outcome = outcome
        self.calls = []

    def __call__(self, path, **kwargs):
        self.calls.append((path, kwargs))
        return self.outcome


def test_report_command_writes_html_and_prints_the_path(tmp_path, capsys):
    run_dir, _ = _run_dir(tmp_path)

    assert main(["report", str(run_dir)]) == 0

    path = run_dir / "report.html"
    assert path.is_file()
    assert str(path) in capsys.readouterr().out


def test_report_command_honors_out_and_is_0600(tmp_path, capsys):
    run_dir, _ = _run_dir(tmp_path)
    out = tmp_path / "elsewhere" / "findings.html"

    assert (
        main(["report", str(run_dir), "--out", str(out)]) == 0
    )

    assert out.is_file()
    assert stat.S_IMODE(out.stat().st_mode) == 0o600
    assert str(out) in capsys.readouterr().out


def test_report_command_prints_json_metadata(tmp_path, capsys):
    run_dir, _ = _run_dir(
        tmp_path, (EXPOSED, NOT_REPRODUCED, NOT_REPRODUCED)
    )

    assert main(["report", str(run_dir), "--json"]) == 0

    data = json.loads(capsys.readouterr().out)
    assert data["run_dir"] == str(run_dir)
    assert data["report"] == str(run_dir / "report.html")
    assert data["snapshot_id"] == SANDBOX_ID
    assert data["counts"] == {
        EXPOSED: 1,
        NOT_REPRODUCED: 2,
        UNVERIFIED: 0,
    }
    assert [finding["probe"] for finding in data["findings"]] == list(PROBES)
    assert data["findings"][0]["proof_status"] == "UNSIGNED"
    assert data["findings"][0]["fingerprint"] is None


def test_report_command_missing_run_dir_is_a_named_error(tmp_path, capsys):
    assert main(["report", str(tmp_path / "missing")]) == 1

    captured = capsys.readouterr()
    assert "REPORT_MISSING" in captured.out
    assert "Traceback" not in captured.out + captured.err


def test_report_command_invalid_json_is_a_named_error(tmp_path, capsys):
    run_dir, _ = _run_dir(tmp_path)
    (run_dir / "results.json").write_text("{not json", encoding="utf-8")

    assert main(["report", str(run_dir)]) == 1

    captured = capsys.readouterr()
    assert "REPORT_MALFORMED" in captured.out
    assert "Traceback" not in captured.out + captured.err


def test_scan_report_writes_the_report_and_preserves_the_verdict(
    repo, tmp_path, monkeypatch, capsys
):
    run_dir, results = _run_dir(
        tmp_path, (EXPOSED, NOT_REPRODUCED, NOT_REPRODUCED)
    )
    fake = FakeScanLocal(_outcome(run_dir, results))
    monkeypatch.setattr("pry.cli.scan_local", fake)

    assert main(["scan", str(repo), "--report"]) == 1

    out = capsys.readouterr().out
    report = run_dir / "report.html"
    assert report.is_file()
    assert "Report: %s" % report in out
    assert "cors: EXPOSED" in out


def test_scan_report_keeps_zero_exit_when_nothing_is_exposed(
    repo, tmp_path, monkeypatch, capsys
):
    run_dir, results = _run_dir(tmp_path)
    fake = FakeScanLocal(_outcome(run_dir, results))
    monkeypatch.setattr("pry.cli.scan_local", fake)

    assert main(["scan", str(repo), "--report"]) == 0

    out = capsys.readouterr().out
    assert str(run_dir / "report.html") in out


def test_scan_report_failure_exits_two(repo, tmp_path, monkeypatch, capsys):
    run_dir, results = _run_dir(tmp_path)
    fake = FakeScanLocal(_outcome(run_dir, results))
    monkeypatch.setattr("pry.cli.scan_local", fake)

    def fail(*args, **kwargs):
        raise ReportError(REPORT_FAILED, "cannot write report: denied")

    monkeypatch.setattr("pry.cli.write_report", fail)

    assert main(["scan", str(repo), "--report"]) == 2

    captured = capsys.readouterr()
    assert "REPORT_FAILED" in captured.out
    assert not (run_dir / "report.html").exists()


def test_scan_report_json_stays_valid_and_includes_the_report(
    repo, tmp_path, monkeypatch, capsys
):
    run_dir, results = _run_dir(tmp_path)
    fake = FakeScanLocal(_outcome(run_dir, results))
    monkeypatch.setattr("pry.cli.scan_local", fake)

    assert main(["scan", str(repo), "--report", "--json"]) == 0

    out = capsys.readouterr().out
    data = json.loads(out)
    assert data["report"] == str(run_dir / "report.html")
    assert "Report:" not in out


def test_scan_prints_a_corpus_warning_to_stderr(
    repo, tmp_path, monkeypatch, capsys
):
    run_dir, results = _run_dir(tmp_path)
    message = "REPORT_FAILED: cannot append corpus: denied"
    fake = FakeScanLocal(_outcome(run_dir, results, corpus_error=message))
    monkeypatch.setattr("pry.cli.scan_local", fake)

    assert main(["scan", str(repo)]) == 0

    captured = capsys.readouterr()
    assert "Warning: corpus not written: %s" % message in captured.err
    assert "Warning" not in captured.out
