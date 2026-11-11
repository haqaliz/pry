"""CLI local Level 2 write gate and configuration tests (AT1, AT5-AT7).

The scan itself is faked: nothing here starts a container or opens a socket.
"""

import json
import os

import pytest

from pry.cli import main
from pry.probe.results import (
    EXPOSED,
    NOT_REPRODUCED,
    ProbeResult,
    summarize,
)
from pry.probe.scan import ScanOutcome
from pry.probe.write import WriteConfig

TARGET = "https://example.com"
RATE_ARGV = ["--rate-limit-endpoint", "/api/ping"]
SSRF_ARGV = ["--ssrf-endpoint", "/api/fetch", "--ssrf-parameter", "url"]
BODY = '{"name": "{{marker}}", "note": "cli-write-secret"}'


def _payload(**overrides):
    data = {
        "method": "POST",
        "endpoint": "/api/write",
        "body": BODY,
        "verify_endpoint": "/api/verify",
        "verify_contains": "{{marker}}",
        "content_type": "application/json",
    }
    data.update(overrides)
    return data


def _write_config_file(tmp_path, data=None, mode=0o600):
    path = tmp_path / "write.json"
    payload = _payload() if data is None else data
    path.write_text(
        payload if isinstance(payload, str) else json.dumps(payload),
        encoding="utf-8",
    )
    os.chmod(str(path), mode)
    return path


def _result(probe, verdict=NOT_REPRODUCED):
    return ProbeResult(
        probe=probe,
        verdict=verdict,
        cause=None,
        evidence="%s checked" % probe,
        request={
            "method": "GET",
            "url": "http://app:8000/",
            "headers": {"User-Agent": "pry/0.1"},
        },
        response={"status": 200, "headers": {}, "body": "ok"},
    )


def _write_result(verdict=NOT_REPRODUCED):
    return ProbeResult(
        probe="write",
        verdict=verdict,
        cause=None,
        evidence="write POST /api/write returned status 201; "
        "verification GET /api/verify returned status 200",
        request={
            "method": "POST",
            "url": "http://app:8000/api/write",
            "headers": {
                "user-agent": "pry/0.1",
                "content-type": "application/json",
            },
        },
        response={
            "status": 201,
            "headers": {},
            "body": '{"ok": true}',
            "verification": {
                "request": {
                    "method": "GET",
                    "url": "http://app:8000/api/verify",
                    "headers": {"user-agent": "pry/0.1"},
                },
                "response": {
                    "status": 200,
                    "headers": {},
                    "body": '{"stored": "pry-0123456789abcdef"}',
                },
            },
        },
    )


def _outcome(tmp_path, write_verdict=NOT_REPRODUCED):
    results = [_result(probe) for probe in ("cors", "errors", "secrets")]
    results.append(_write_result(write_verdict))
    return ScanOutcome(
        snapshot={
            "sandbox_id": "pry-abc123",
            "target": {"path": "/repo", "kind": "static"},
        },
        results=results,
        results_path=tmp_path / "run" / "results.json",
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


@pytest.fixture
def repo(tmp_path):
    path = tmp_path / "repo"
    path.mkdir()
    return path


def _gate(monkeypatch, capsys, argv, outcome=None):
    local = FakeScanLocal(outcome)
    live = FakeScanLive(outcome)
    monkeypatch.setattr("pry.cli.scan_local", local)
    monkeypatch.setattr("pry.cli.scan_live", live)

    code = main(argv)

    return code, capsys.readouterr().out, local, live


def test_local_level2_forwards_a_valid_write_config(
    repo, tmp_path, monkeypatch, capsys
):
    path = _write_config_file(tmp_path)

    code, out, local, live = _gate(
        monkeypatch,
        capsys,
        [
            "scan",
            str(repo),
            "--level",
            "2",
            "--confirm",
            "--write-config",
            str(path),
        ],
        _outcome(tmp_path),
    )

    assert code == 0
    assert live.calls == []
    _path, kwargs = local.calls[0]
    assert kwargs["write_config"] == WriteConfig(
        method="POST",
        endpoint="/api/write",
        body=BODY,
        verify_endpoint="/api/verify",
        verify_contains="{{marker}}",
        content_type="application/json",
    )
    assert "write: NOT_REPRODUCED" in out
    assert str(path) not in out
    assert "cli-write-secret" not in out


def test_an_exposed_write_exits_one(repo, tmp_path, monkeypatch, capsys):
    path = _write_config_file(tmp_path)

    code, out, _local, _live = _gate(
        monkeypatch,
        capsys,
        [
            "scan",
            str(repo),
            "--level",
            "2",
            "--confirm",
            "--write-config",
            str(path),
        ],
        _outcome(tmp_path, EXPOSED),
    )

    assert code == 1
    assert "write: EXPOSED" in out


def test_level2_requires_confirm(repo, tmp_path, monkeypatch, capsys):
    path = _write_config_file(tmp_path)

    code, out, local, _live = _gate(
        monkeypatch,
        capsys,
        ["scan", str(repo), "--level", "2", "--write-config", str(path)],
    )

    assert code == 2
    assert "CONFIRMATION_REQUIRED" in out
    assert local.calls == []


def test_level2_requires_a_write_config(repo, monkeypatch, capsys):
    code, out, local, _live = _gate(
        monkeypatch,
        capsys,
        ["scan", str(repo), "--level", "2", "--confirm"],
    )

    assert code == 2
    assert "WRITE_CONFIG_REQUIRED" in out
    assert local.calls == []


@pytest.mark.parametrize("level", ["0", "1"])
def test_level0_and_level1_refuse_a_write_config(
    repo, tmp_path, monkeypatch, capsys, level
):
    path = _write_config_file(tmp_path)
    argv = ["scan", str(repo), "--level", level, "--write-config", str(path)]
    if level == "1":
        argv.append("--confirm")
    argv += ["--idor-config", "unused.json"]

    code, out, local, _live = _gate(monkeypatch, capsys, argv)

    assert code == 2
    assert "WRITE_REQUIRES_LEVEL2" in out
    assert local.calls == []


def test_level2_accepts_ssrf_and_rate_limit_with_confirm(
    repo, tmp_path, monkeypatch, capsys
):
    path = _write_config_file(tmp_path)

    code, out, local, _live = _gate(
        monkeypatch,
        capsys,
        ["scan", str(repo), "--level", "2", "--confirm"]
        + SSRF_ARGV
        + RATE_ARGV
        + ["--write-config", str(path)],
        _outcome(tmp_path),
    )

    assert code == 0
    _path, kwargs = local.calls[0]
    assert kwargs["write_config"].endpoint == "/api/write"
    assert kwargs["ssrf_config"].endpoint == "/api/fetch"
    assert kwargs["rate_limit_config"].endpoint == "/api/ping"
    assert "LEVEL1_CHECK_REQUIRED" not in out


@pytest.mark.parametrize(
    "data,mode",
    [
        (_payload(), 0o644),
        ("{not json", 0o600),
        ("[]", 0o600),
        (_payload(endpoint="http://evil.invalid/api"), 0o600),
        (_payload(method="DELETE"), 0o600),
        (_payload(body="no marker"), 0o600),
        (_payload(verify_endpoint="/api/verify?x=1"), 0o600),
    ],
)
def test_an_invalid_write_config_never_scans(
    repo, tmp_path, monkeypatch, capsys, data, mode
):
    path = _write_config_file(tmp_path, data, mode)

    code, out, local, _live = _gate(
        monkeypatch,
        capsys,
        [
            "scan",
            str(repo),
            "--level",
            "2",
            "--confirm",
            "--write-config",
            str(path),
        ],
    )

    assert code == 2
    assert "WRITE_CONFIG_INVALID" in out
    assert local.calls == []
    assert str(path) not in out
    assert "cli-write-secret" not in out


def test_a_missing_write_config_never_scans(repo, tmp_path, monkeypatch, capsys):
    path = tmp_path / "missing.json"

    code, out, local, _live = _gate(
        monkeypatch,
        capsys,
        [
            "scan",
            str(repo),
            "--level",
            "2",
            "--confirm",
            "--write-config",
            str(path),
        ],
    )

    assert code == 2
    assert "WRITE_CONFIG_INVALID" in out
    assert local.calls == []
    assert str(path) not in out


@pytest.mark.parametrize("mode", [0o600, 0o644])
def test_a_url_with_a_write_config_without_level2_is_refused(
    tmp_path, monkeypatch, capsys, mode
):
    path = _write_config_file(tmp_path, mode=mode)

    code, out, local, live = _gate(
        monkeypatch,
        capsys,
        ["scan", TARGET, "--write-config", str(path)],
    )

    assert code == 2
    assert "WRITE_REQUIRES_LEVEL2" in out
    assert local.calls == []
    assert live.calls == []
    assert str(path) not in out


def test_scan_help_lists_the_write_config_flag(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["scan", "--help"])

    assert exc.value.code == 0
    out = capsys.readouterr().out
    assert "--write-config" in out
    assert "level 2" in out.lower()
