"""CLI opt-in header observation tests (AT1, AT2, AT4, AT5)."""

import json

import pytest

from pry.cli import main
from pry.own.target import normalize_target
from pry.own.tokens import TokenSigner
from pry.probe.headers import OBSERVED
from pry.probe.results import (
    EXPOSED,
    NOT_REPRODUCED,
    UNVERIFIED,
    ProbeResult,
    summarize,
)
from pry.probe.scan import ScanOutcome

TARGET = "https://example.com"
PROBES = ("cors", "errors", "secrets")


@pytest.fixture(autouse=True)
def ownership_key(tmp_path, monkeypatch):
    monkeypatch.setenv("PRY_KEY_FILE", str(tmp_path / "ownership.key"))


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


def _observation(status=OBSERVED):
    return {
        "probe": "headers",
        "status": status,
        "evidence": "6 recommended response headers checked on /: 1 present, "
        "5 missing (hardening observation)",
        "request": {
            "method": "GET",
            "url": "http://app:8000/",
            "headers": {"user-agent": "pry/0.1"},
        },
        "response": {"status": 200, "headers": {}, "body": "ok"},
        "missing": ["content-security-policy"],
        "present": ["x-frame-options"],
    }


def _unverified_observation():
    return {
        "probe": "headers",
        "status": UNVERIFIED,
        "evidence": "TARGET_UNREACHABLE: transport failure: connection refused",
        "request": {
            "method": "GET",
            "url": "http://app:8000/",
            "headers": {"user-agent": "pry/0.1"},
        },
        "response": None,
        "missing": [],
        "present": [],
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


@pytest.fixture
def repo(tmp_path):
    path = tmp_path / "repo"
    path.mkdir()
    return path


def test_local_scan_headers_forwards_the_flag_and_prints_the_observation(
    repo, tmp_path, monkeypatch, capsys
):
    outcome = _outcome(
        tmp_path, [_floor_result(probe) for probe in PROBES], [_observation()]
    )

    code, out, local, _live = _gate(
        monkeypatch, capsys, ["scan", str(repo), "--headers"], outcome
    )

    assert code == 0
    _path, kwargs = local.calls[0]
    assert kwargs["headers"] is True
    assert "headers: OBSERVED" in out
    assert "hardening observation" in out
    assert "Results: %s" % (tmp_path / "run" / "results.json") in out


def test_local_scan_without_headers_keeps_the_existing_call(
    repo, tmp_path, monkeypatch, capsys
):
    outcome = _outcome(tmp_path, [_floor_result(probe) for probe in PROBES])

    code, _out, local, _live = _gate(
        monkeypatch, capsys, ["scan", str(repo)], outcome
    )

    assert code == 0
    assert "headers" not in local.calls[0][1]


def test_local_scan_headers_does_not_require_confirmation_or_a_level(
    repo, tmp_path, monkeypatch, capsys
):
    outcome = _outcome(
        tmp_path, [_floor_result(probe) for probe in PROBES], [_observation()]
    )

    code, _out, local, _live = _gate(
        monkeypatch,
        capsys,
        ["scan", str(repo), "--level", "0", "--headers"],
        outcome,
    )

    assert code == 0
    assert local.calls[0][1]["headers"] is True


def test_live_scan_headers_forwards_the_flag_and_prints_the_observation(
    tmp_path, monkeypatch, capsys
):
    outcome = _outcome(
        tmp_path, [_floor_result(probe) for probe in PROBES], [_observation()]
    )
    token = _token()

    code, out, _local, live = _gate(
        monkeypatch,
        capsys,
        ["scan", TARGET, "--token", token, "--headers"],
        outcome,
    )

    assert code == 0
    url, sent_token, kwargs = live.calls[0]
    assert (url, sent_token) == (TARGET, token)
    assert kwargs["headers"] is True
    assert "headers: OBSERVED" in out
    assert "hardening observation" in out
    assert token not in out


def test_live_scan_without_headers_keeps_the_existing_call(
    tmp_path, monkeypatch, capsys
):
    outcome = _outcome(tmp_path, [_floor_result(probe) for probe in PROBES])

    code, _out, _local, live = _gate(
        monkeypatch, capsys, ["scan", TARGET, "--token", _token()], outcome
    )

    assert code == 0
    assert "headers" not in live.calls[0][2]


def test_live_scan_headers_does_not_skip_the_token_check(
    monkeypatch, capsys
):
    code, out, _local, live = _gate(
        monkeypatch, capsys, ["scan", TARGET, "--headers"]
    )

    assert code == 2
    assert live.calls == []
    assert "UNVERIFIED" in out


def test_json_includes_the_header_observation_without_a_verdict(
    repo, tmp_path, monkeypatch, capsys
):
    outcome = _outcome(
        tmp_path, [_floor_result(probe) for probe in PROBES], [_observation()]
    )

    code, out, _local, _live = _gate(
        monkeypatch, capsys, ["scan", str(repo), "--headers", "--json"], outcome
    )

    assert code == 0
    data = json.loads(out)
    assert data["summary"] == {
        EXPOSED: 0,
        NOT_REPRODUCED: 3,
        UNVERIFIED: 0,
    }
    assert len(data["observations"]) == 1
    stored = data["observations"][0]
    assert stored["probe"] == "headers"
    assert stored["status"] == OBSERVED
    assert stored["missing"] == ["content-security-policy"]
    assert stored["present"] == ["x-frame-options"]
    assert "verdict" not in stored
    assert "proof" not in stored
    assert [entry["probe"] for entry in data["results"]] == list(PROBES)


def test_a_transport_failure_is_printed_as_unverified(
    repo, tmp_path, monkeypatch, capsys
):
    outcome = _outcome(
        tmp_path,
        [_floor_result(probe) for probe in PROBES],
        [_unverified_observation()],
    )

    code, out, _local, _live = _gate(
        monkeypatch, capsys, ["scan", str(repo), "--headers"], outcome
    )

    assert code == 0
    assert "headers: UNVERIFIED" in out
    assert "TARGET_UNREACHABLE" in out


def test_the_exit_code_still_follows_exposed_results(
    repo, tmp_path, monkeypatch, capsys
):
    outcome = _outcome(
        tmp_path,
        [_floor_result("cors", EXPOSED), _floor_result("errors")],
        [_observation()],
    )

    code, _out, _local, _live = _gate(
        monkeypatch, capsys, ["scan", str(repo), "--headers"], outcome
    )

    assert code == 1
