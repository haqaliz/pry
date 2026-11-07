"""CLI live URL scan tests (AT1, AT2, AT5)."""

import json
from dataclasses import asdict

import pytest

from pry.cli import main
from pry.own.target import normalize_target
from pry.own.tokens import TokenSigner
from pry.probe.results import EXPOSED, NOT_REPRODUCED, ProbeResult, summarize
from pry.probe.scan import ScanOutcome

TARGET = "https://app.example.com"
PROBES = ("cors", "errors", "secrets")


@pytest.fixture(autouse=True)
def ownership_key(tmp_path, monkeypatch):
    path = tmp_path / "ownership.key"
    monkeypatch.setenv("PRY_KEY_FILE", str(path))
    return path


def _token(target=TARGET):
    return TokenSigner().issue(normalize_target(target), "dns_txt")


def _result(probe, verdict=NOT_REPRODUCED, path="/"):
    return ProbeResult(
        probe=probe,
        verdict=verdict,
        cause=None,
        evidence="%s checked" % probe,
        request={
            "method": "GET",
            "url": TARGET + path,
            "headers": {"User-Agent": "pry/0.1"},
        },
        response={"status": 200, "headers": {}, "body": "ok"},
    )


def _write_run(tmp_path, results):
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    snapshot = {
        "version": 1,
        "sandbox_id": "live-abc123",
        "created_at": "2026-11-08T00:00:00Z",
        "target": {
            "path": TARGET,
            "kind": "live",
            "url": TARGET,
            "ownership_proof": "dns_txt",
        },
        "project": {},
        "sandbox": {},
        "result": {"status": "ready"},
    }
    (run_dir / "snapshot.json").write_text(json.dumps(snapshot), encoding="utf-8")
    (run_dir / "results.json").write_text(
        json.dumps(
            {
                "version": 1,
                "target": {
                    "sandbox_id": "live-abc123",
                    "path": TARGET,
                    "kind": "live",
                },
                "results": [asdict(result) for result in results],
                "summary": summarize(results),
                "created_at": "2026-11-08T00:00:00Z",
            }
        ),
        encoding="utf-8",
    )
    return run_dir


def _outcome(tmp_path, verdicts, extra=None):
    results = [
        _result(probe, verdict) for probe, verdict in zip(PROBES, verdicts)
    ]
    results.extend(extra or [])
    run_dir = _write_run(tmp_path, results)
    return ScanOutcome(
        snapshot=json.loads(
            (run_dir / "snapshot.json").read_text(encoding="utf-8")
        ),
        results=results,
        results_path=run_dir / "results.json",
        summary=summarize(results),
    )


class FakeScanLive:
    """Stand-in for pry.cli.scan_live; never touches the network."""

    def __init__(self, outcome=None, error=None):
        self.outcome = outcome
        self.error = error
        self.calls = []

    def __call__(self, url, token, **kwargs):
        self.calls.append((url, token, kwargs))
        if self.error is not None:
            raise self.error
        return self.outcome


def test_live_scan_with_exposed_probe_exits_one(
    tmp_path, monkeypatch, capsys
):
    fake = FakeScanLive(_outcome(tmp_path, [EXPOSED, NOT_REPRODUCED, NOT_REPRODUCED]))
    monkeypatch.setattr("pry.cli.scan_live", fake)
    token = _token()

    assert main(["scan", TARGET, "--token", token]) == 1

    assert fake.calls == [(TARGET, token, {"endpoints": [], "out": None})]
    out = capsys.readouterr().out
    assert "cors: EXPOSED: cors checked" in out
    assert "errors: NOT_REPRODUCED: errors checked" in out
    assert "Results: %s" % (tmp_path / "run" / "results.json") in out


def test_live_scan_without_exposed_probe_exits_zero(
    tmp_path, monkeypatch, capsys
):
    fake = FakeScanLive(_outcome(tmp_path, [NOT_REPRODUCED] * 3))
    monkeypatch.setattr("pry.cli.scan_live", fake)

    assert main(["scan", TARGET, "--token", _token()]) == 0
    assert "cors: NOT_REPRODUCED" in capsys.readouterr().out


@pytest.mark.parametrize(
    "argv",
    [
        ["scan", TARGET],
        ["scan", TARGET, "--token", ""],
        ["scan", TARGET, "--token", "garbage"],
    ],
)
def test_live_scan_with_a_missing_or_invalid_token_never_scans(
    argv, monkeypatch, capsys
):
    fake = FakeScanLive()
    monkeypatch.setattr("pry.cli.scan_live", fake)

    assert main(argv) == 2
    assert fake.calls == []
    assert "UNVERIFIED" in capsys.readouterr().out


def test_live_scan_with_a_token_for_another_target_never_scans(
    monkeypatch, capsys
):
    fake = FakeScanLive()
    monkeypatch.setattr("pry.cli.scan_live", fake)
    token = _token("https://other.example")

    assert main(["scan", TARGET, "--token", token]) == 2
    assert fake.calls == []
    assert "TOKEN_TARGET_MISMATCH" in capsys.readouterr().out


def test_live_scan_report_flag_writes_and_prints_the_path(
    tmp_path, monkeypatch, capsys
):
    fake = FakeScanLive(_outcome(tmp_path, [NOT_REPRODUCED] * 3))
    monkeypatch.setattr("pry.cli.scan_live", fake)

    assert main(["scan", TARGET, "--token", _token(), "--report"]) == 0

    report = tmp_path / "run" / "report.html"
    assert report.is_file()
    assert "Report: %s" % report in capsys.readouterr().out


def test_live_scan_json_includes_results_and_report(
    tmp_path, monkeypatch, capsys
):
    fake = FakeScanLive(_outcome(tmp_path, [NOT_REPRODUCED] * 3))
    monkeypatch.setattr("pry.cli.scan_live", fake)
    token = _token()

    assert main(["scan", TARGET, "--token", token, "--report", "--json"]) == 0

    raw = capsys.readouterr().out
    data = json.loads(raw)
    assert set(data) == {
        "snapshot",
        "results",
        "summary",
        "results_path",
        "report",
    }
    assert data["snapshot"]["sandbox_id"] == "live-abc123"
    assert [entry["probe"] for entry in data["results"]] == list(PROBES)
    assert data["report"] == str(tmp_path / "run" / "report.html")
    assert token not in raw


def test_live_scan_forwards_declared_endpoints(
    tmp_path, monkeypatch, capsys
):
    fake = FakeScanLive(
        _outcome(
            tmp_path,
            [NOT_REPRODUCED] * 3,
            extra=[_result("unauth", EXPOSED, "/api/users")],
        )
    )
    monkeypatch.setattr("pry.cli.scan_live", fake)

    assert (
        main(
            [
                "scan",
                TARGET,
                "--token",
                _token(),
                "--endpoint",
                "/api/users",
            ]
        )
        == 1
    )
    assert fake.calls[0][2]["endpoints"] == ["/api/users"]
    assert "unauth: EXPOSED" in capsys.readouterr().out


@pytest.mark.parametrize(
    "bad", ["http://evil.invalid", "api/users", "/api users"]
)
def test_live_scan_rejects_invalid_endpoints_before_scanning(
    bad, monkeypatch, capsys
):
    fake = FakeScanLive()
    monkeypatch.setattr("pry.cli.scan_live", fake)

    assert (
        main(
            [
                "scan",
                TARGET,
                "--token",
                _token(),
                "--endpoint",
                "/api/users",
                "--endpoint",
                bad,
            ]
        )
        == 2
    )
    assert fake.calls == []
    assert "INVALID_ENDPOINT" in capsys.readouterr().out


def test_local_scan_is_unchanged_and_never_runs_the_live_path(
    tmp_path, monkeypatch, capsys
):
    repo = tmp_path / "repo"
    repo.mkdir()
    local_outcome = ScanOutcome(
        snapshot={"sandbox_id": "pry-abc123"},
        results=[_result(probe) for probe in PROBES],
        results_path=tmp_path / "local" / "results.json",
        summary=summarize([_result(probe) for probe in PROBES]),
    )
    local_calls = []
    monkeypatch.setattr(
        "pry.cli.scan_local",
        lambda path, **kwargs: local_calls.append((path, kwargs)) or local_outcome,
    )
    live_calls = []
    monkeypatch.setattr(
        "pry.cli.scan_live", lambda *a, **k: live_calls.append((a, k))
    )

    assert main(["scan", str(repo)]) == 0
    assert local_calls[0][0] == str(repo)
    assert live_calls == []
    assert "Results: %s" % (tmp_path / "local" / "results.json") in (
        capsys.readouterr().out
    )
