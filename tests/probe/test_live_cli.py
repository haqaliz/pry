"""CLI live URL scan tests (AT1, AT2, AT5)."""

import json
import os
from dataclasses import asdict

import pytest

from pry.cli import main
from pry.own.target import normalize_target
from pry.own.tokens import TokenSigner
from pry.probe.idor import IdorConfig
from pry.probe.results import EXPOSED, NOT_REPRODUCED, ProbeResult, summarize
from pry.probe.scan import ScanOutcome

TARGET = "https://app.example.com"
PROBES = ("cors", "errors", "secrets")
SECRET_A = "cli-alice-secret"
SECRET_B = "cli-bob-secret"


@pytest.fixture(autouse=True)
def ownership_key(tmp_path, monkeypatch):
    path = tmp_path / "ownership.key"
    monkeypatch.setenv("PRY_KEY_FILE", str(path))
    return path


def _token(target=TARGET):
    return TokenSigner().issue(normalize_target(target), "dns_txt")


def _idor_payload(headers_a=None):
    return {
        "identity_a": {
            "headers": {"Cookie": "sid=" + SECRET_A}
            if headers_a is None
            else headers_a
        },
        "identity_b": {"headers": {"Cookie": "sid=" + SECRET_B}},
        "object_a": "/api/orders/1",
        "object_b": "/api/orders/2",
    }


def _write_idor_config(tmp_path, data=None, mode=0o600):
    path = tmp_path / "idor.json"
    payload = _idor_payload() if data is None else data
    path.write_text(json.dumps(payload), encoding="utf-8")
    os.chmod(str(path), mode)
    return path


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

    assert fake.calls == [
        (TARGET, token, {"endpoints": [], "out": None, "idor_config": None})
    ]
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
        "observations",
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


def test_live_scan_forwards_a_valid_idor_config(
    tmp_path, monkeypatch, capsys
):
    path = _write_idor_config(tmp_path)
    fake = FakeScanLive(
        _outcome(
            tmp_path,
            [NOT_REPRODUCED] * 3,
            extra=[_result("idor", NOT_REPRODUCED, "/api/orders/2")],
        )
    )
    monkeypatch.setattr("pry.cli.scan_live", fake)
    token = _token()

    assert (
        main(
            [
                "scan",
                TARGET,
                "--token",
                token,
                "--idor-config",
                str(path),
                "--json",
            ]
        )
        == 0
    )

    assert len(fake.calls) == 1
    url, sent_token, kwargs = fake.calls[0]
    assert (url, sent_token) == (TARGET, token)
    config = kwargs["idor_config"]
    assert isinstance(config, IdorConfig)
    assert config.headers_a == {"Cookie": "sid=" + SECRET_A}
    assert config.headers_b == {"Cookie": "sid=" + SECRET_B}
    assert (config.object_a, config.object_b) == ("/api/orders/1", "/api/orders/2")

    raw = capsys.readouterr().out
    data = json.loads(raw)
    assert data["results"][-1]["probe"] == "idor"
    assert SECRET_A not in raw
    assert SECRET_B not in raw
    assert str(path) not in raw


def test_live_scan_report_includes_the_idor_result(
    tmp_path, monkeypatch, capsys
):
    path = _write_idor_config(tmp_path)
    fake = FakeScanLive(
        _outcome(
            tmp_path,
            [NOT_REPRODUCED] * 3,
            extra=[_result("idor", NOT_REPRODUCED, "/api/orders/2")],
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
                "--idor-config",
                str(path),
                "--report",
            ]
        )
        == 0
    )

    rendered = (tmp_path / "run" / "report.html").read_text(encoding="utf-8")
    assert "idor" in rendered
    assert SECRET_A not in rendered
    assert SECRET_B not in rendered
    assert str(path) not in rendered


def test_live_scan_without_an_idor_config_lists_no_idor(
    tmp_path, monkeypatch, capsys
):
    fake = FakeScanLive(_outcome(tmp_path, [NOT_REPRODUCED] * 3))
    monkeypatch.setattr("pry.cli.scan_live", fake)

    assert main(["scan", TARGET, "--token", _token(), "--json"]) == 0

    assert fake.calls[0][2]["idor_config"] is None
    data = json.loads(capsys.readouterr().out)
    assert [entry["probe"] for entry in data["results"]] == list(PROBES)


def test_local_scan_with_an_idor_config_is_rejected_before_scanning(
    tmp_path, monkeypatch, capsys
):
    repo = tmp_path / "repo"
    repo.mkdir()
    path = _write_idor_config(tmp_path)
    local_calls = []
    live_calls = []
    monkeypatch.setattr(
        "pry.cli.scan_local", lambda *a, **k: local_calls.append((a, k))
    )
    monkeypatch.setattr(
        "pry.cli.scan_live", lambda *a, **k: live_calls.append((a, k))
    )

    assert main(["scan", str(repo), "--idor-config", str(path)]) == 2

    out = capsys.readouterr().out
    assert "IDOR_REQUIRES_LIVE" in out
    assert local_calls == []
    assert live_calls == []
    assert str(path) not in out
    assert SECRET_A not in out
    assert SECRET_B not in out


def test_live_scan_with_a_group_readable_idor_config_never_scans(
    tmp_path, monkeypatch, capsys
):
    path = _write_idor_config(tmp_path, mode=0o644)
    fake = FakeScanLive()
    monkeypatch.setattr("pry.cli.scan_live", fake)

    assert (
        main(["scan", TARGET, "--token", _token(), "--idor-config", str(path)])
        == 2
    )

    assert fake.calls == []
    out = capsys.readouterr().out
    assert "IDOR_CONFIG_INVALID" in out
    assert str(path) not in out
    assert SECRET_A not in out
    assert SECRET_B not in out


def test_live_scan_with_a_malformed_idor_config_never_scans(
    tmp_path, monkeypatch, capsys
):
    path = tmp_path / "idor.json"
    path.write_text("{not json", encoding="utf-8")
    os.chmod(str(path), 0o600)
    fake = FakeScanLive()
    monkeypatch.setattr("pry.cli.scan_live", fake)

    assert (
        main(["scan", TARGET, "--token", _token(), "--idor-config", str(path)])
        == 2
    )

    assert fake.calls == []
    out = capsys.readouterr().out
    assert "IDOR_CONFIG_INVALID" in out
    assert str(path) not in out


def test_live_scan_with_a_header_injection_in_the_idor_config_never_scans(
    tmp_path, monkeypatch, capsys
):
    data = _idor_payload(
        headers_a={"Cookie": "sid=" + SECRET_A + "\r\nX-Injected: 1"}
    )
    path = _write_idor_config(tmp_path, data)
    fake = FakeScanLive()
    monkeypatch.setattr("pry.cli.scan_live", fake)

    assert (
        main(["scan", TARGET, "--token", _token(), "--idor-config", str(path)])
        == 2
    )

    assert fake.calls == []
    out = capsys.readouterr().out
    assert "IDOR_CONFIG_INVALID" in out
    assert str(path) not in out
    assert SECRET_A not in out


def test_live_scan_with_a_missing_idor_config_never_scans(
    tmp_path, monkeypatch, capsys
):
    path = tmp_path / "missing.json"
    fake = FakeScanLive()
    monkeypatch.setattr("pry.cli.scan_live", fake)

    assert (
        main(["scan", TARGET, "--token", _token(), "--idor-config", str(path)])
        == 2
    )

    assert fake.calls == []
    out = capsys.readouterr().out
    assert "IDOR_CONFIG_INVALID" in out
    assert str(path) not in out


def test_live_scan_never_prints_idor_credentials_or_the_config_path(
    tmp_path, monkeypatch, capsys
):
    path = _write_idor_config(tmp_path)
    fake = FakeScanLive(
        _outcome(
            tmp_path,
            [NOT_REPRODUCED] * 3,
            extra=[_result("idor", NOT_REPRODUCED, "/api/orders/2")],
        )
    )
    monkeypatch.setattr("pry.cli.scan_live", fake)
    token = _token()

    assert (
        main(
            [
                "scan",
                TARGET,
                "--token",
                token,
                "--idor-config",
                str(path),
                "--report",
                "--json",
            ]
        )
        == 0
    )

    texts = [
        capsys.readouterr().out,
        (tmp_path / "run" / "results.json").read_text(encoding="utf-8"),
        (tmp_path / "run" / "report.html").read_text(encoding="utf-8"),
    ]
    for text in texts:
        assert token not in text
        assert SECRET_A not in text
        assert SECRET_B not in text
        assert str(path) not in text
