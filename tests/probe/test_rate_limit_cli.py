"""CLI Level 1 rate-limit gate, configuration, and output (AT4-AT7)."""

import json

import pytest

from pry.cli import main
from pry.own.target import normalize_target
from pry.own.tokens import TokenSigner
from pry.probe.rate_limit import OBSERVED, THROTTLED, RateLimitConfig
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
SSRF_ARGV = ["--ssrf-endpoint", "/api/fetch", "--ssrf-parameter", "url"]
RATE_ARGV = ["--rate-limit-endpoint", "/api/ping"]
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


def _floor_result(probe, verdict=NOT_REPRODUCED):
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


def _ssrf_result():
    return ProbeResult(
        probe="ssrf",
        verdict=EXPOSED,
        cause=None,
        evidence="the callback recorded GET /nonce",
        request={
            "method": "GET",
            "url": "http://app:8000/api/fetch?url=http%3A%2F%2Fcallback",
            "headers": {"User-Agent": "pry/0.1"},
        },
        response={
            "status": 200,
            "method": "GET",
            "path": "/nonce",
            "headers": {"User-Agent": "python-urllib"},
        },
    )


def _observation(status=OBSERVED, evidence=None, count=10):
    return {
        "probe": "rate_limit",
        "status": status,
        "evidence": evidence
        or "10 requests accepted without throttling (hardening observation)",
        "request": {
            "method": "GET",
            "url": "http://app:8000/api/ping",
            "headers": {"user-agent": "pry/0.1"},
        },
        "response": {"status": 200, "headers": {}, "body": "ok"},
        "count": count,
        "statuses": [200] * count,
    }


def _outcome(tmp_path, results, observations=None):
    return ScanOutcome(
        snapshot={
            "sandbox_id": "pry-abc123",
            "target": {"path": "/repo", "kind": "static"},
        },
        results=results,
        results_path=tmp_path / "run" / "results.json",
        summary=summarize(results),
        observations=list(observations or []),
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


def _gate(monkeypatch, capsys, argv, outcome=None):
    local = FakeScanLocal(outcome)
    live = FakeScanLive(outcome)
    monkeypatch.setattr("pry.cli.scan_local", local)
    monkeypatch.setattr("pry.cli.scan_live", live)

    code = main(argv)

    return code, capsys.readouterr().out, local, live


def test_rate_limit_forwards_the_default_count_and_prints_the_observation(
    repo, tmp_path, monkeypatch, capsys
):
    outcome = _outcome(tmp_path, [_floor_result(p) for p in PROBES], [_observation()])

    code, out, local, _live = _gate(
        monkeypatch,
        capsys,
        ["scan", str(repo), "--level", "1", "--confirm"] + RATE_ARGV,
        outcome,
    )

    assert code == 0
    _path, kwargs = local.calls[0]
    assert kwargs["rate_limit_config"] == RateLimitConfig(
        endpoint="/api/ping", count=10
    )
    assert "ssrf_config" not in kwargs
    assert "rate_limit: OBSERVED" in out
    assert "hardening observation" in out


def test_rate_limit_forwards_an_explicit_count(repo, tmp_path, monkeypatch, capsys):
    outcome = _outcome(
        tmp_path, [_floor_result(p) for p in PROBES], [_observation(count=5)]
    )

    code, _out, local, _live = _gate(
        monkeypatch,
        capsys,
        ["scan", str(repo), "--level", "1", "--confirm"]
        + RATE_ARGV
        + ["--rate-limit-count", "5"],
        outcome,
    )

    assert code == 0
    assert local.calls[0][1]["rate_limit_config"] == RateLimitConfig(
        endpoint="/api/ping", count=5
    )


def test_a_count_without_an_endpoint_is_refused(repo, monkeypatch, capsys):
    code, out, local, _live = _gate(
        monkeypatch,
        capsys,
        ["scan", str(repo), "--level", "1", "--confirm", "--rate-limit-count", "5"],
    )

    assert code == 2
    assert "RATE_LIMIT_CONFIG_REQUIRED" in out
    assert local.calls == []


@pytest.mark.parametrize("count", ["0", "21", "-1"])
def test_an_out_of_bounds_count_is_refused(
    repo, monkeypatch, capsys, count
):
    code, out, local, _live = _gate(
        monkeypatch,
        capsys,
        ["scan", str(repo), "--level", "1", "--confirm"]
        + RATE_ARGV
        + ["--rate-limit-count", count],
    )

    assert code == 2
    assert "RATE_LIMIT_CONFIG_INVALID" in out
    assert local.calls == []


@pytest.mark.parametrize(
    "endpoint",
    [
        "http://evil.invalid",
        "api/ping",
        "/api/ping?x=1",
        "/api/ping#frag",
    ],
)
def test_an_invalid_endpoint_is_refused(
    repo, monkeypatch, capsys, endpoint
):
    code, out, local, _live = _gate(
        monkeypatch,
        capsys,
        ["scan", str(repo), "--level", "1", "--confirm"]
        + ["--rate-limit-endpoint", endpoint],
    )

    assert code == 2
    assert "RATE_LIMIT_CONFIG_INVALID" in out
    assert local.calls == []


def test_level1_rate_limit_requires_confirm(repo, monkeypatch, capsys):
    code, out, local, _live = _gate(
        monkeypatch,
        capsys,
        ["scan", str(repo), "--level", "1"] + RATE_ARGV,
    )

    assert code == 2
    assert "CONFIRMATION_REQUIRED" in out
    assert local.calls == []


def test_level1_requires_at_least_one_check(repo, monkeypatch, capsys):
    code, out, local, _live = _gate(
        monkeypatch,
        capsys,
        ["scan", str(repo), "--level", "1", "--confirm"],
    )

    assert code == 2
    assert "LEVEL1_CHECK_REQUIRED" in out
    assert local.calls == []


def test_ssrf_and_rate_limit_can_run_together(repo, tmp_path, monkeypatch, capsys):
    outcome = _outcome(
        tmp_path,
        [_floor_result(p) for p in PROBES] + [_ssrf_result()],
        [_observation()],
    )

    code, out, local, _live = _gate(
        monkeypatch,
        capsys,
        ["scan", str(repo), "--level", "1", "--confirm"]
        + SSRF_ARGV
        + RATE_ARGV,
        outcome,
    )

    assert code == 1
    _path, kwargs = local.calls[0]
    assert kwargs["ssrf_config"] == SsrfConfig(
        endpoint="/api/fetch", parameter="url"
    )
    assert kwargs["rate_limit_config"] == RateLimitConfig(
        endpoint="/api/ping", count=10
    )
    assert "ssrf: EXPOSED" in out
    assert "rate_limit: OBSERVED" in out


@pytest.mark.parametrize(
    "extra",
    [
        RATE_ARGV,
        ["--rate-limit-count", "10"],
        RATE_ARGV + ["--rate-limit-count", "10"],
    ],
)
def test_rate_limit_flags_at_level0_are_refused(
    repo, monkeypatch, capsys, extra
):
    code, out, local, _live = _gate(
        monkeypatch,
        capsys,
        ["scan", str(repo), "--level", "0"] + extra,
    )

    assert code == 2
    assert "RATE_LIMIT_REQUIRES_LEVEL1" in out
    assert local.calls == []


def test_level2_is_refused_before_any_rate_limit_work(
    repo, monkeypatch, capsys
):
    code, out, local, _live = _gate(
        monkeypatch,
        capsys,
        ["scan", str(repo), "--level", "2", "--confirm"] + RATE_ARGV,
    )

    assert code == 2
    assert "INTENSITY_INSUFFICIENT" in out
    assert local.calls == []


@pytest.mark.parametrize(
    "extra",
    [
        ["--level", "1", "--confirm"] + RATE_ARGV,
        RATE_ARGV,
        ["--rate-limit-count", "5"],
    ],
)
def test_a_url_refuses_level1_or_rate_limit_flags(monkeypatch, capsys, extra):
    code, out, local, live = _gate(
        monkeypatch,
        capsys,
        ["scan", TARGET, "--token", _token()] + extra,
    )

    assert code == 2
    assert "LEVEL1_REQUIRES_LOCAL" in out
    assert local.calls == []
    assert live.calls == []


def test_json_includes_observations_and_leaves_the_summary_alone(
    repo, tmp_path, monkeypatch, capsys
):
    outcome = _outcome(
        tmp_path,
        [_floor_result(p) for p in PROBES],
        [
            _observation(
                status=THROTTLED,
                evidence="throttled at request 4/10: status 429",
                count=4,
            )
        ],
    )

    code, out, _local, _live = _gate(
        monkeypatch,
        capsys,
        ["scan", str(repo), "--level", "1", "--confirm", "--json"] + RATE_ARGV,
        outcome,
    )

    assert code == 0
    data = json.loads(out)
    assert data["summary"] == {
        EXPOSED: 0,
        NOT_REPRODUCED: 3,
        UNVERIFIED: 0,
    }
    assert len(data["observations"]) == 1
    assert data["observations"][0]["probe"] == "rate_limit"
    assert data["observations"][0]["status"] == THROTTLED
    assert data["observations"][0]["statuses"] == [200] * 4
    assert "proof" not in data["observations"][0]
    assert [entry["probe"] for entry in data["results"]] == list(PROBES)


def test_the_exit_code_still_follows_exposed_results(
    repo, tmp_path, monkeypatch, capsys
):
    outcome = _outcome(
        tmp_path,
        [_floor_result("cors", EXPOSED), _floor_result("errors")],
        [_observation()],
    )

    code, _out, _local, _live = _gate(
        monkeypatch,
        capsys,
        ["scan", str(repo), "--level", "1", "--confirm"] + RATE_ARGV,
        outcome,
    )

    assert code == 1
    assert outcome.observations
