"""CLI live rate-limit gate (AT1, AT4-AT7)."""

import pytest

from pry.cli import main
from pry.own.target import normalize_target
from pry.own.tokens import TokenSigner
from pry.probe.rate_limit import (
    LIVE_RATE_LIMIT_DEFAULT_COUNT,
    OBSERVED,
    THROTTLED,
    RateLimitConfig,
)
from pry.probe.results import NOT_REPRODUCED, ProbeResult, summarize
from pry.probe.scan import ScanOutcome

TARGET = "https://example.com"
RATE_ARGV = ["--rate-limit-endpoint", "/login"]
PROBES = ("cors", "errors", "secrets", "database")


@pytest.fixture(autouse=True)
def ownership_key(tmp_path, monkeypatch):
    monkeypatch.setenv("PRY_KEY_FILE", str(tmp_path / "ownership.key"))


def _token():
    return TokenSigner().issue(normalize_target(TARGET), "dns_txt")


def _result(probe):
    return ProbeResult(
        probe=probe,
        verdict=NOT_REPRODUCED,
        cause=None,
        evidence="%s checked" % probe,
        request={
            "method": "GET",
            "url": TARGET + "/",
            "headers": {"User-Agent": "pry/0.1"},
        },
        response={"status": 200, "headers": {}, "body": "ok"},
    )


def _observation(status=OBSERVED, count=5):
    return {
        "probe": "rate_limit",
        "status": status,
        "evidence": "%d requests accepted without throttling "
        "(hardening observation)" % count,
        "request": {
            "method": "GET",
            "url": TARGET + "/login",
            "headers": {"user-agent": "pry/0.1"},
        },
        "response": {"status": 200, "headers": {}, "body": "ok"},
        "count": count,
        "statuses": [200] * count,
    }


def _outcome(tmp_path, observations=None):
    results = [_result(probe) for probe in PROBES]
    return ScanOutcome(
        snapshot={"sandbox_id": "live-abc123"},
        results=results,
        results_path=tmp_path / "run" / "results.json",
        summary=summarize(results),
        observations=list(observations or []),
    )


class FakeScanLive:
    def __init__(self, outcome):
        self.outcome = outcome
        self.calls = []

    def __call__(self, url, token, **kwargs):
        self.calls.append((url, token, kwargs))
        return self.outcome


def _gate(monkeypatch, argv, outcome):
    fake = FakeScanLive(outcome)
    monkeypatch.setattr("pry.cli.scan_live", fake)
    return main(argv), fake


def test_live_level1_forwards_the_default_count_and_prints_the_observation(
    tmp_path, monkeypatch, capsys
):
    outcome = _outcome(tmp_path, [_observation()])

    code, fake = _gate(
        monkeypatch,
        ["scan", TARGET, "--token", _token(), "--level", "1", "--confirm"]
        + RATE_ARGV,
        outcome,
    )

    assert code == 0
    _url, _token_value, kwargs = fake.calls[0]
    assert kwargs["rate_limit_config"] == RateLimitConfig(
        endpoint="/login", count=LIVE_RATE_LIMIT_DEFAULT_COUNT
    )
    assert "rate_limit: OBSERVED" in capsys.readouterr().out


def test_live_level1_forwards_an_explicit_count(tmp_path, monkeypatch):
    outcome = _outcome(tmp_path, [_observation(count=3)])

    code, fake = _gate(
        monkeypatch,
        ["scan", TARGET, "--token", _token(), "--level", "1", "--confirm"]
        + RATE_ARGV
        + ["--rate-limit-count", "3"],
        outcome,
    )

    assert code == 0
    assert fake.calls[0][2]["rate_limit_config"] == RateLimitConfig(
        endpoint="/login", count=3
    )


def test_a_live_count_over_five_is_refused_before_any_scan(
    tmp_path, monkeypatch, capsys
):
    code, fake = _gate(
        monkeypatch,
        ["scan", TARGET, "--token", _token(), "--level", "1", "--confirm"]
        + RATE_ARGV
        + ["--rate-limit-count", "6"],
        _outcome(tmp_path),
    )

    assert code == 2
    assert "RATE_LIMIT_CONFIG_INVALID" in capsys.readouterr().out
    assert fake.calls == []


def test_live_level1_requires_confirmation(tmp_path, monkeypatch, capsys):
    code, fake = _gate(
        monkeypatch,
        ["scan", TARGET, "--token", _token(), "--level", "1"] + RATE_ARGV,
        _outcome(tmp_path),
    )

    assert code == 2
    assert "CONFIRMATION_REQUIRED" in capsys.readouterr().out
    assert fake.calls == []


def test_live_level1_requires_a_rate_limit_endpoint(
    tmp_path, monkeypatch, capsys
):
    code, fake = _gate(
        monkeypatch,
        ["scan", TARGET, "--token", _token(), "--level", "1", "--confirm"],
        _outcome(tmp_path),
    )

    assert code == 2
    assert "LEVEL1_CHECK_REQUIRED" in capsys.readouterr().out
    assert fake.calls == []


def test_live_ssrf_flags_are_still_local_only(tmp_path, monkeypatch, capsys):
    code, fake = _gate(
        monkeypatch,
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
        ],
        _outcome(tmp_path),
    )

    assert code == 2
    assert "SSRF_REQUIRES_LOCAL" in capsys.readouterr().out
    assert fake.calls == []


def test_rate_limit_flags_without_level1_are_refused(tmp_path, monkeypatch, capsys):
    code, fake = _gate(
        monkeypatch,
        ["scan", TARGET, "--token", _token()] + RATE_ARGV,
        _outcome(tmp_path),
    )

    assert code == 2
    assert "RATE_LIMIT_REQUIRES_LEVEL1" in capsys.readouterr().out
    assert fake.calls == []


def test_a_throttled_observation_does_not_change_the_exit_code(
    tmp_path, monkeypatch, capsys
):
    outcome = _outcome(tmp_path, [_observation(status=THROTTLED, count=2)])

    code, _fake = _gate(
        monkeypatch,
        ["scan", TARGET, "--token", _token(), "--level", "1", "--confirm"]
        + RATE_ARGV,
        outcome,
    )

    assert code == 0
    assert "rate_limit: THROTTLED" in capsys.readouterr().out
