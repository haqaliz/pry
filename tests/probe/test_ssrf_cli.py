"""CLI Level 1 SSRF gate and confirmation matrix (AT3-AT6, AT9)."""

import json
from dataclasses import asdict

import pytest

from pry.cli import main
from pry.own.target import normalize_target
from pry.own.tokens import TokenSigner
from pry.probe.results import (
    EXPOSED,
    NOT_REPRODUCED,
    UNVERIFIED,
    ProbeResult,
    summarize,
)
from pry.probe.scan import ScanOutcome
from pry.probe.ssrf import SsrfConfig

TARGET = "https://example.com"
NONCE = "0123456789abcdef0123456789abcdef"
HIT_PATH = "/" + NONCE
SSRF_ARGV = [
    "--ssrf-endpoint",
    "/api/fetch",
    "--ssrf-parameter",
    "url",
]
PROBES = ("cors", "errors", "secrets")


@pytest.fixture(autouse=True)
def ownership_key(tmp_path, monkeypatch):
    monkeypatch.setenv("PRY_KEY_FILE", str(tmp_path / "ownership.key"))


@pytest.fixture
def repo(tmp_path):
    path = tmp_path / "repo"
    path.mkdir()
    return path


def _token(target=TARGET):
    return TokenSigner().issue(normalize_target(target), "dns_txt")


def _floor_result(probe, verdict=NOT_REPRODUCED, url="http://app:8000/"):
    return ProbeResult(
        probe=probe,
        verdict=verdict,
        cause=None,
        evidence="%s checked" % probe,
        request={
            "method": "GET",
            "url": url,
            "headers": {"User-Agent": "pry/0.1"},
        },
        response={"status": 200, "headers": {}, "body": "ok"},
    )


def _ssrf_result(verdict=EXPOSED, cause=None):
    return ProbeResult(
        probe="ssrf",
        verdict=verdict,
        cause=cause,
        evidence=(
            "the app responded with status 200 and fetched the callback URL: "
            "the callback recorded GET %s" % HIT_PATH
        ),
        request={
            "method": "GET",
            "url": "http://app:8000/api/fetch?url=http%3A%2F%2Fpry-callback"
            "%3A9000%2F" + NONCE,
            "headers": {"User-Agent": "pry/0.1"},
        },
        response={
            "status": 200,
            "method": "GET",
            "path": HIT_PATH,
            "headers": {"User-Agent": "python-urllib"},
        },
    )


def _results(ssrf=None):
    results = [_floor_result(probe) for probe in PROBES]
    if ssrf is not None:
        results.append(ssrf)
    return results


def _outcome(tmp_path, results):
    return ScanOutcome(
        snapshot={
            "sandbox_id": "pry-abc123",
            "target": {"path": "/repo", "kind": "static"},
        },
        results=results,
        results_path=tmp_path / "run" / "results.json",
        summary=summarize(results),
    )


def _write_run(tmp_path, results):
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    snapshot = {
        "version": 1,
        "sandbox_id": "pry-abc123",
        "created_at": "2026-11-10T00:00:00Z",
        "target": {"path": "/repo", "kind": "static"},
        "project": {},
        "sandbox": {},
        "result": {"status": "ready"},
    }
    (run_dir / "snapshot.json").write_text(
        json.dumps(snapshot), encoding="utf-8"
    )
    (run_dir / "results.json").write_text(
        json.dumps(
            {
                "version": 1,
                "target": {
                    "sandbox_id": "pry-abc123",
                    "path": "/repo",
                    "kind": "static",
                },
                "results": [asdict(result) for result in results],
                "summary": summarize(results),
                "created_at": "2026-11-10T00:00:00Z",
            }
        ),
        encoding="utf-8",
    )
    return ScanOutcome(
        snapshot=snapshot,
        results=results,
        results_path=run_dir / "results.json",
        summary=summarize(results),
    )


class FakeScanLocal:
    def __init__(self, outcome=None):
        self.outcome = outcome
        self.calls = []

    def __call__(self, path, **kwargs):
        self.calls.append((path, kwargs))
        return self.outcome


class FakeScanLive:
    def __init__(self, outcome=None):
        self.outcome = outcome
        self.calls = []

    def __call__(self, url, token, **kwargs):
        self.calls.append((url, token, kwargs))
        return self.outcome


def _gate(monkeypatch, capsys, argv):
    local = FakeScanLocal()
    live = FakeScanLive()
    monkeypatch.setattr("pry.cli.scan_local", local)
    monkeypatch.setattr("pry.cli.scan_live", live)

    code = main(argv)

    return code, capsys.readouterr().out, local, live


def test_level1_confirm_ssrf_forwards_the_config_and_appends_the_result(
    repo, tmp_path, monkeypatch, capsys
):
    fake = FakeScanLocal(_outcome(tmp_path, _results(_ssrf_result())))
    monkeypatch.setattr("pry.cli.scan_local", fake)

    code = main(
        [
            "scan",
            str(repo),
            "--level",
            "1",
            "--confirm",
            "--endpoint",
            "/api/users",
        ]
        + SSRF_ARGV
    )

    assert code == 1
    path, kwargs = fake.calls[0]
    assert path == str(repo)
    assert kwargs["ssrf_config"] == SsrfConfig(
        endpoint="/api/fetch", parameter="url"
    )
    assert kwargs["endpoints"] == ["/api/users"]
    out = capsys.readouterr().out
    assert "cors: NOT_REPRODUCED" in out
    assert "ssrf: EXPOSED" in out
    assert HIT_PATH in out


def test_level1_json_includes_the_ssrf_result(repo, tmp_path, monkeypatch, capsys):
    fake = FakeScanLocal(_outcome(tmp_path, _results(_ssrf_result())))
    monkeypatch.setattr("pry.cli.scan_local", fake)

    assert (
        main(
            ["scan", str(repo), "--level", "1", "--confirm", "--json"]
            + SSRF_ARGV
        )
        == 1
    )

    data = json.loads(capsys.readouterr().out)
    assert [entry["probe"] for entry in data["results"]] == [
        "cors",
        "errors",
        "secrets",
        "ssrf",
    ]
    assert data["results"][-1]["verdict"] == EXPOSED
    assert data["results"][-1]["response"]["path"] == HIT_PATH
    assert data["summary"] == {
        EXPOSED: 1,
        NOT_REPRODUCED: 3,
        UNVERIFIED: 0,
    }


def test_level1_report_includes_the_ssrf_result(
    repo, tmp_path, monkeypatch, capsys
):
    outcome = _write_run(tmp_path, _results(_ssrf_result()))
    fake = FakeScanLocal(outcome)
    monkeypatch.setattr("pry.cli.scan_local", fake)

    assert (
        main(
            ["scan", str(repo), "--level", "1", "--confirm", "--report"]
            + SSRF_ARGV
        )
        == 1
    )

    report = (tmp_path / "run" / "report.html").read_text(encoding="utf-8")
    assert "ssrf" in report
    assert EXPOSED in report
    assert HIT_PATH in report


def test_level1_requires_confirm(repo, monkeypatch, capsys):
    code, out, local, _live = _gate(
        monkeypatch,
        capsys,
        ["scan", str(repo), "--level", "1"] + SSRF_ARGV,
    )

    assert code == 2
    assert "CONFIRMATION_REQUIRED" in out
    assert local.calls == []


def test_level1_without_confirm_reports_confirmation_before_config(
    repo, monkeypatch, capsys
):
    code, out, local, _live = _gate(
        monkeypatch, capsys, ["scan", str(repo), "--level", "1"]
    )

    assert code == 2
    assert "CONFIRMATION_REQUIRED" in out
    assert "SSRF_CONFIG_REQUIRED" not in out
    assert local.calls == []


@pytest.mark.parametrize(
    "extra",
    [
        ["--ssrf-endpoint", "/api/fetch"],
        ["--ssrf-parameter", "url"],
    ],
)
def test_level1_requires_both_ssrf_flags(
    repo, monkeypatch, capsys, extra
):
    code, out, local, _live = _gate(
        monkeypatch,
        capsys,
        ["scan", str(repo), "--level", "1", "--confirm"] + extra,
    )

    assert code == 2
    assert "SSRF_CONFIG_REQUIRED" in out
    assert local.calls == []


@pytest.mark.parametrize(
    "extra",
    [
        SSRF_ARGV,
        ["--ssrf-endpoint", "/api/fetch"],
        ["--ssrf-parameter", "url"],
    ],
)
def test_ssrf_flags_at_level0_are_refused(
    repo, monkeypatch, capsys, extra
):
    code, out, local, _live = _gate(
        monkeypatch, capsys, ["scan", str(repo), "--level", "0"] + extra
    )

    assert code == 2
    assert "SSRF_REQUIRES_LEVEL1" in out
    assert local.calls == []


def test_level2_without_a_write_config_is_refused_before_ssrf_work(
    repo, monkeypatch, capsys
):
    code, out, local, _live = _gate(
        monkeypatch,
        capsys,
        ["scan", str(repo), "--level", "2", "--confirm"] + SSRF_ARGV,
    )

    assert code == 2
    assert "WRITE_CONFIG_REQUIRED" in out
    assert local.calls == []


@pytest.mark.parametrize(
    "extra",
    [
        ["--ssrf-endpoint", "http://evil.invalid/fetch", "--ssrf-parameter", "url"],
        ["--ssrf-endpoint", "/api/fetch", "--ssrf-parameter", "1url"],
        ["--ssrf-endpoint", "/api/fetch", "--ssrf-parameter", "url name"],
        ["--ssrf-endpoint", "api/fetch", "--ssrf-parameter", "url"],
    ],
)
def test_invalid_ssrf_config_never_scans(repo, monkeypatch, capsys, extra):
    code, out, local, _live = _gate(
        monkeypatch,
        capsys,
        ["scan", str(repo), "--level", "1", "--confirm"] + extra,
    )

    assert code == 2
    assert "SSRF_CONFIG_INVALID" in out
    assert local.calls == []


@pytest.mark.parametrize(
    "extra,cause",
    [
        (["--level", "1", "--confirm"] + SSRF_ARGV, "SSRF_CONFIG_REQUIRED"),
        (["--level", "1"], "CONFIRMATION_REQUIRED"),
        (["--level", "0"] + SSRF_ARGV, "SSRF_REQUIRES_LEVEL1"),
    ],
)
def test_a_url_needs_a_live_callback_for_ssrf(monkeypatch, capsys, extra, cause):
    code, out, local, live = _gate(
        monkeypatch,
        capsys,
        ["scan", TARGET, "--token", _token()] + extra,
    )

    assert code == 2
    assert cause in out
    assert local.calls == []
    assert live.calls == []


def test_a_url_at_level0_without_ssrf_flags_still_scans(
    tmp_path, monkeypatch, capsys
):
    fake = FakeScanLive(_outcome(tmp_path, _results()))
    monkeypatch.setattr("pry.cli.scan_live", fake)

    assert main(["scan", TARGET, "--token", _token()]) == 0
    assert fake.calls[0][0] == TARGET
    assert "cors: NOT_REPRODUCED" in capsys.readouterr().out


def test_local_level0_forwards_no_ssrf_config(repo, tmp_path, monkeypatch):
    fake = FakeScanLocal(_outcome(tmp_path, _results()))
    monkeypatch.setattr("pry.cli.scan_local", fake)

    assert main(["scan", str(repo)]) == 0
    _path, kwargs = fake.calls[0]
    assert "ssrf_config" not in kwargs
