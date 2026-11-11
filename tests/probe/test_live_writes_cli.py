"""CLI live Level 2 write gate (AT5-AT7)."""

import json
import os

import pytest

from pry.cli import main
from pry.own.target import normalize_target
from pry.own.tokens import TokenSigner
from pry.probe.results import EXPOSED, NOT_REPRODUCED, ProbeResult, summarize
from pry.probe.scan import ScanOutcome
from pry.probe.write import WriteConfig

TARGET = "https://example.com"
BODY = '{"name":"{{marker}}"}'


def _payload():
    return {
        "method": "POST",
        "endpoint": "/api/write",
        "body": BODY,
        "verify_endpoint": "/api/write",
        "verify_contains": "{{marker}}",
        "content_type": "application/json",
    }


def _config_file(tmp_path, mode=0o600):
    path = tmp_path / "write.json"
    path.write_text(json.dumps(_payload()), encoding="utf-8")
    os.chmod(str(path), mode)
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


def _write_result(verdict=NOT_REPRODUCED):
    return ProbeResult(
        probe="write",
        verdict=verdict,
        cause=None,
        evidence="POST /api/write returned status 201; verification GET "
        "/api/write returned status 200",
        request={
            "method": "POST",
            "url": TARGET + "/api/write",
            "headers": {
                "user-agent": "pry/0.1",
                "content-type": "application/json",
            },
        },
        response={
            "status": 201,
            "headers": {},
            "body": '{"created":true}',
            "verification": {
                "request": {
                    "method": "GET",
                    "url": TARGET + "/api/write",
                    "headers": {"user-agent": "pry/0.1"},
                },
                "response": {
                    "status": 200,
                    "headers": {},
                    "body": '{"name":"pry-abc123"}',
                },
            },
        },
    )


def _outcome(tmp_path, write_verdict=NOT_REPRODUCED):
    results = [_result(probe) for probe in ("cors", "errors", "secrets")]
    results.append(_write_result(write_verdict))
    return ScanOutcome(
        snapshot={"sandbox_id": "live-abc123"},
        results=results,
        results_path=tmp_path / "run" / "results.json",
        summary=summarize(results),
    )


class FakeScanLive:
    def __init__(self, outcome):
        self.outcome = outcome
        self.calls = []

    def __call__(self, url, token, **kwargs):
        self.calls.append((url, token, kwargs))
        return self.outcome


def _gate(monkeypatch, tmp_path, argv, outcome=None):
    fake = FakeScanLive(outcome or _outcome(tmp_path))
    monkeypatch.setattr("pry.cli.scan_live", fake)
    return main(argv), fake


@pytest.fixture(autouse=True)
def ownership_key(tmp_path, monkeypatch):
    monkeypatch.setenv("PRY_KEY_FILE", str(tmp_path / "ownership.key"))


def test_live_level2_write_runs_with_both_confirmations(
    tmp_path, monkeypatch, capsys
):
    path = _config_file(tmp_path)
    code, fake = _gate(
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
        ],
        _outcome(tmp_path, EXPOSED),
    )

    assert code == 1
    _url, _token_value, kwargs = fake.calls[0]
    assert kwargs["write_config"] == WriteConfig(
        method="POST",
        endpoint="/api/write",
        body=BODY,
        verify_endpoint="/api/write",
        verify_contains="{{marker}}",
    )
    assert "write: EXPOSED" in capsys.readouterr().out
    assert str(path) not in json.dumps(kwargs, default=str)


def test_live_level2_write_requires_the_extra_confirmation(
    tmp_path, monkeypatch, capsys
):
    path = _config_file(tmp_path)
    code, fake = _gate(
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
            "--write-config",
            str(path),
        ],
    )

    assert code == 2
    assert "LIVE_WRITE_CONFIRMATION_REQUIRED" in capsys.readouterr().out
    assert fake.calls == []


def test_live_level2_write_requires_the_std_confirmation(
    tmp_path, monkeypatch, capsys
):
    path = _config_file(tmp_path)
    code, fake = _gate(
        monkeypatch,
        tmp_path,
        [
            "scan",
            TARGET,
            "--token",
            _token(),
            "--level",
            "2",
            "--confirm-live-write",
            "--write-config",
            str(path),
        ],
    )

    assert code == 2
    assert "CONFIRMATION_REQUIRED" in capsys.readouterr().out
    assert fake.calls == []


def test_live_level2_write_requires_a_token(tmp_path, monkeypatch, capsys):
    path = _config_file(tmp_path)
    code, fake = _gate(
        monkeypatch,
        tmp_path,
        [
            "scan",
            TARGET,
            "--level",
            "2",
            "--confirm",
            "--confirm-live-write",
            "--write-config",
            str(path),
        ],
    )

    assert code == 2
    assert "TOKEN_MALFORMED" in capsys.readouterr().out
    assert fake.calls == []


def test_live_level2_without_a_write_config_is_refused(
    tmp_path, monkeypatch, capsys
):
    code, fake = _gate(
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
        ],
    )

    assert code == 2
    assert "WRITE_CONFIG_REQUIRED" in capsys.readouterr().out
    assert fake.calls == []


def test_confirm_live_write_without_a_config_is_refused(
    tmp_path, monkeypatch, capsys
):
    code, fake = _gate(
        monkeypatch,
        tmp_path,
        ["scan", TARGET, "--token", _token(), "--confirm-live-write"],
    )

    assert code == 2
    assert "LIVE_WRITE_CONFIRMATION_UNEXPECTED" in capsys.readouterr().out
    assert fake.calls == []


def test_live_write_config_at_level0_is_refused(tmp_path, monkeypatch, capsys):
    path = _config_file(tmp_path)
    code, fake = _gate(
        monkeypatch,
        tmp_path,
        ["scan", TARGET, "--token", _token(), "--write-config", str(path)],
    )

    assert code == 2
    assert "WRITE_REQUIRES_LEVEL2" in capsys.readouterr().out
    assert fake.calls == []


def test_a_live_write_config_must_be_0600(tmp_path, monkeypatch, capsys):
    path = _config_file(tmp_path, mode=0o644)
    code, fake = _gate(
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
        ],
    )

    assert code == 2
    out = capsys.readouterr().out
    assert "WRITE_CONFIG_INVALID" in out
    assert str(path) not in out
    assert fake.calls == []


def test_live_ssrf_can_run_with_a_level2_write(tmp_path, monkeypatch, capsys):
    path = _config_file(tmp_path)
    code, fake = _gate(
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
            "--ssrf-endpoint",
            "/api/fetch",
            "--ssrf-parameter",
            "url",
            "--ssrf-callback-url",
            "https://callback.example/pry",
        ],
    )

    assert code == 0
    assert fake.calls[0][2]["ssrf_config"].callback_url == (
        "https://callback.example/pry"
    )
    assert fake.calls[0][2]["write_config"].endpoint == "/api/write"


def test_live_level2_write_can_include_a_rate_limit_observation(
    tmp_path, monkeypatch
):
    path = _config_file(tmp_path)
    code, fake = _gate(
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
            "--rate-limit-endpoint",
            "/login",
            "--rate-limit-count",
            "3",
        ],
    )

    assert code == 0
    assert fake.calls[0][2]["write_config"].endpoint == "/api/write"
    assert fake.calls[0][2]["rate_limit_config"].endpoint == "/login"
    assert fake.calls[0][2]["rate_limit_config"].count == 3
