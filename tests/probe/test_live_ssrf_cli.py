"""CLI live SSRF gate (AT6-AT8)."""

import json
import os

import pytest

from pry.cli import main
from pry.own.target import normalize_target
from pry.own.tokens import TokenSigner
from pry.probe.live_ssrf import LiveSsrfConfig
from pry.probe.results import (
    EXPOSED,
    NOT_REPRODUCED,
    ProbeError,
    ProbeResult,
    summarize,
)
from pry.probe.scan import ScanOutcome

TARGET = "https://example.com"
CALLBACK = "https://callback.example/pry"
SSRF_ARGV = [
    "--ssrf-endpoint",
    "/api/fetch",
    "--ssrf-parameter",
    "url",
    "--ssrf-callback-url",
    CALLBACK,
]


@pytest.fixture(autouse=True)
def ownership_key(tmp_path, monkeypatch):
    monkeypatch.setenv("PRY_KEY_FILE", str(tmp_path / "ownership.key"))


@pytest.fixture
def repo(tmp_path):
    path = tmp_path / "repo"
    path.mkdir()
    return path


def _token():
    return TokenSigner().issue(normalize_target(TARGET), "dns_txt")


def _result(probe, verdict=NOT_REPRODUCED):
    return ProbeResult(
        probe=probe,
        verdict=verdict,
        cause=None,
        evidence="%s checked" % probe,
        request={
            "method": "GET",
            "url": TARGET + "/",
            "headers": {"User-Agent": "pry/0.1"},
        },
        response={"status": 200, "headers": {}, "body": "ok"},
    )


def _ssrf_result(verdict=EXPOSED):
    return ProbeResult(
        probe="ssrf",
        verdict=verdict,
        cause=None,
        evidence="callback recorded GET /nonce on poll 1/3 after app returned "
        "status 200",
        request={
            "method": "GET",
            "url": TARGET + "/api/fetch?url=" + CALLBACK + "%2Fnonce",
            "headers": {"user-agent": "pry/0.1"},
        },
        response={
            "status": 200,
            "headers": {},
            "body": "ok",
            "callback": {
                "request": {
                    "method": "GET",
                    "url": CALLBACK + "/nonce",
                    "headers": {"user-agent": "pry/0.1"},
                },
                "response": {"status": 200, "headers": {}, "body": ""},
                "attempts": 1,
            },
        },
    )


def _outcome(tmp_path, ssrf_verdict=None):
    results = [_result(probe) for probe in ("cors", "errors", "secrets")]
    if ssrf_verdict is not None:
        results.append(_ssrf_result(ssrf_verdict))
    return ScanOutcome(
        snapshot={"sandbox_id": "live-abc123"},
        results=results,
        results_path=tmp_path / "run" / "results.json",
        summary=summarize(results),
    )


def _write_config_file(tmp_path):
    path = tmp_path / "write.json"
    path.write_text(
        json.dumps(
            {
                "method": "POST",
                "endpoint": "/api/write",
                "body": '{"name":"{{marker}}"}',
                "verify_endpoint": "/api/write",
                "verify_contains": "{{marker}}",
                "content_type": "application/json",
            }
        ),
        encoding="utf-8",
    )
    os.chmod(str(path), 0o600)
    return path


class FakeScanLive:
    def __init__(self, outcome=None, error=None):
        self.outcome = outcome
        self.error = error
        self.calls = []

    def __call__(self, url, token, **kwargs):
        self.calls.append((url, token, kwargs))
        if self.error is not None:
            raise self.error
        return self.outcome


class FakeScanLocal:
    def __init__(self):
        self.calls = []

    def __call__(self, path, **kwargs):
        self.calls.append((path, kwargs))
        return None


def _gate(monkeypatch, tmp_path, argv, outcome=None, error=None):
    local = FakeScanLocal()
    live = FakeScanLive(outcome or _outcome(tmp_path), error)
    monkeypatch.setattr("pry.cli.scan_local", local)
    monkeypatch.setattr("pry.cli.scan_live", live)
    return main(argv), local, live


def test_live_ssrf_runs_with_level1_confirm_and_a_token(
    tmp_path, monkeypatch, capsys
):
    code, _local, live = _gate(
        monkeypatch,
        tmp_path,
        ["scan", TARGET, "--token", _token(), "--level", "1", "--confirm"]
        + SSRF_ARGV,
        _outcome(tmp_path, EXPOSED),
    )

    assert code == 1
    url, _token_value, kwargs = live.calls[0]
    assert url == TARGET
    assert kwargs["ssrf_config"] == LiveSsrfConfig(
        endpoint="/api/fetch", parameter="url", callback_url=CALLBACK
    )
    assert "ssrf: EXPOSED" in capsys.readouterr().out


def test_live_ssrf_requires_confirm(tmp_path, monkeypatch, capsys):
    code, _local, live = _gate(
        monkeypatch,
        tmp_path,
        ["scan", TARGET, "--token", _token(), "--level", "1"] + SSRF_ARGV,
    )

    assert code == 2
    assert "CONFIRMATION_REQUIRED" in capsys.readouterr().out
    assert live.calls == []


def test_live_ssrf_requires_a_token(tmp_path, monkeypatch, capsys):
    code, _local, live = _gate(
        monkeypatch,
        tmp_path,
        ["scan", TARGET, "--level", "1", "--confirm"] + SSRF_ARGV,
    )

    assert code == 2
    assert "TOKEN_MALFORMED" in capsys.readouterr().out
    assert live.calls == []


@pytest.mark.parametrize(
    "extra",
    (
        ["--ssrf-endpoint", "/api/fetch", "--ssrf-parameter", "url"],
        ["--ssrf-endpoint", "/api/fetch", "--ssrf-callback-url", CALLBACK],
        ["--ssrf-parameter", "url", "--ssrf-callback-url", CALLBACK],
    ),
)
def test_live_ssrf_requires_all_three_flags(
    tmp_path, monkeypatch, capsys, extra
):
    code, _local, live = _gate(
        monkeypatch,
        tmp_path,
        ["scan", TARGET, "--token", _token(), "--level", "1", "--confirm"]
        + extra,
    )

    assert code == 2
    assert "SSRF_CONFIG_REQUIRED" in capsys.readouterr().out
    assert live.calls == []


def test_live_ssrf_at_level0_is_refused(tmp_path, monkeypatch, capsys):
    code, _local, live = _gate(
        monkeypatch,
        tmp_path,
        ["scan", TARGET, "--token", _token()] + SSRF_ARGV,
    )

    assert code == 2
    assert "SSRF_REQUIRES_LEVEL1" in capsys.readouterr().out
    assert live.calls == []


def test_live_ssrf_rejects_an_http_callback(tmp_path, monkeypatch, capsys):
    code, _local, live = _gate(
        monkeypatch,
        tmp_path,
        [
            "scan",
            TARGET,
            "--token",
            _token(),
            "--level",
            "1",
            "--confirm",
            "--ssrf-endpoint",
            "/api/fetch",
            "--ssrf-parameter",
            "url",
            "--ssrf-callback-url",
            "http://callback.example/pry",
        ],
    )

    assert code == 2
    assert "SSRF_CALLBACK_INVALID" in capsys.readouterr().out
    assert live.calls == []


def test_a_same_origin_callback_error_exits_2(tmp_path, monkeypatch, capsys):
    code, _local, live = _gate(
        monkeypatch,
        tmp_path,
        ["scan", TARGET, "--token", _token(), "--level", "1", "--confirm"]
        + SSRF_ARGV,
        error=ProbeError(
            "SSRF_CALLBACK_SAME_ORIGIN", "the callback is on the target origin"
        ),
    )

    assert code == 2
    assert "SSRF_CALLBACK_SAME_ORIGIN" in capsys.readouterr().out
    assert len(live.calls) == 1


def test_a_local_ssrf_with_a_callback_url_is_refused(
    repo, monkeypatch, capsys
):
    code, local, _live = _gate(
        monkeypatch,
        repo,
        ["scan", str(repo), "--level", "1", "--confirm"]
        + SSRF_ARGV,
    )

    assert code == 2
    assert "SSRF_CALLBACK_LOCAL" in capsys.readouterr().out
    assert local.calls == []


def test_a_local_callback_url_without_other_flags_is_refused(
    repo, monkeypatch, capsys
):
    code, local, _live = _gate(
        monkeypatch,
        repo,
        ["scan", str(repo), "--ssrf-callback-url", CALLBACK],
    )

    assert code == 2
    assert "SSRF_CALLBACK_LOCAL" in capsys.readouterr().out
    assert local.calls == []


def test_live_level2_can_combine_a_write_and_ssrf(tmp_path, monkeypatch, capsys):
    path = _write_config_file(tmp_path)
    code, _local, live = _gate(
        monkeypatch,
        tmp_path,
        [
            "scan",
            TARGET,
            "--token",
            _token(),
            "--level",
            "2",
            "--confirm",
            "--confirm-live-write",
            "--write-config",
            str(path),
        ]
        + SSRF_ARGV,
    )

    assert code == 0
    _url, _token_value, kwargs = live.calls[0]
    assert kwargs["write_config"].endpoint == "/api/write"
    assert kwargs["ssrf_config"] == LiveSsrfConfig(
        endpoint="/api/fetch", parameter="url", callback_url=CALLBACK
    )
