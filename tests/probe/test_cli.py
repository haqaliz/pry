"""CLI local scan routing tests (AT7, AT8, AT14)."""

import json

import pytest

from pry.cli import main
from pry.intake.errors import BUILD_FAILED, REPO_NOT_FOUND, IntakeError
from pry.own.target import normalize_target
from pry.own.tokens import TokenSigner
from pry.probe.results import (
    EXPOSED,
    NOT_REPRODUCED,
    UNVERIFIED,
    ProbeError,
    ProbeResult,
    summarize,
)
from pry.probe.scan import ScanOutcome
from pry.proof import PROOF_FAILED, ProofError

TARGET = "https://example.com"
PROBES = ("cors", "errors", "secrets")


@pytest.fixture(autouse=True)
def temp_key(tmp_path, monkeypatch):
    monkeypatch.setenv("PRY_KEY_FILE", str(tmp_path / "ownership.key"))


def _token(target=TARGET):
    return TokenSigner().issue(normalize_target(target), "dns_txt")


def _probe_result(probe, verdict=NOT_REPRODUCED):
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


def _endpoint_result(path="/api/users", verdict=EXPOSED):
    return ProbeResult(
        probe="unauth",
        verdict=verdict,
        cause=None,
        evidence=(
            "declared-protected path %s returned status 200 with "
            "application/json and no credentials" % path
        ),
        request={
            "method": "GET",
            "url": "http://app:8000" + path,
            "headers": {"User-Agent": "pry/0.1"},
        },
        response={
            "status": 200,
            "headers": {"content-type": "application/json"},
            "body": '{"id": 1}',
        },
    )


def _outcome(tmp_path, verdicts, extra=None):
    results = [
        _probe_result(probe, verdict) for probe, verdict in zip(PROBES, verdicts)
    ]
    results.extend(extra or [])
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
    """Stand-in for pry.cli.scan_local; never touches Docker."""

    def __init__(self, outcome=None, error=None):
        self.outcome = outcome
        self.error = error
        self.calls = []

    def __call__(self, path, **kwargs):
        self.calls.append((path, kwargs))
        if self.error is not None:
            raise self.error
        return self.outcome


@pytest.fixture
def repo(tmp_path):
    path = tmp_path / "repo"
    path.mkdir()
    return path


def test_local_scan_with_exposed_probe_exits_one(repo, tmp_path, monkeypatch, capsys):
    fake = FakeScanLocal(
        _outcome(tmp_path, [EXPOSED, NOT_REPRODUCED, NOT_REPRODUCED])
    )
    monkeypatch.setattr("pry.cli.scan_local", fake)

    assert main(["scan", str(repo)]) == 1

    out = capsys.readouterr().out
    assert "cors: EXPOSED: cors checked" in out
    assert "errors: NOT_REPRODUCED: errors checked" in out
    assert "secrets: NOT_REPRODUCED: secrets checked" in out
    assert "Results: %s" % (tmp_path / "run" / "results.json") in out
    path, kwargs = fake.calls[0]
    assert path == str(repo)
    assert kwargs == {
        "out": None,
        "timeout": None,
        "port": None,
        "endpoints": [],
    }


def test_local_scan_without_exposed_probe_exits_zero(repo, tmp_path, monkeypatch, capsys):
    fake = FakeScanLocal(_outcome(tmp_path, [NOT_REPRODUCED, NOT_REPRODUCED, UNVERIFIED]))
    monkeypatch.setattr("pry.cli.scan_local", fake)

    assert main(["scan", str(repo)]) == 0

    out = capsys.readouterr().out
    assert "cors: NOT_REPRODUCED" in out
    assert "secrets: UNVERIFIED" in out


def test_local_scan_json_prints_the_full_result(repo, tmp_path, monkeypatch, capsys):
    fake = FakeScanLocal(
        _outcome(tmp_path, [EXPOSED, NOT_REPRODUCED, NOT_REPRODUCED])
    )
    monkeypatch.setattr("pry.cli.scan_local", fake)

    assert main(["scan", str(repo), "--json"]) == 1

    data = json.loads(capsys.readouterr().out)
    assert set(data) == {"snapshot", "results", "summary", "results_path"}
    assert data["snapshot"]["sandbox_id"] == "pry-abc123"
    assert data["results_path"] == str(tmp_path / "run" / "results.json")
    assert [entry["probe"] for entry in data["results"]] == list(PROBES)
    assert [entry["verdict"] for entry in data["results"]] == [
        EXPOSED,
        NOT_REPRODUCED,
        NOT_REPRODUCED,
    ]
    assert data["summary"] == {
        EXPOSED: 1,
        NOT_REPRODUCED: 2,
        UNVERIFIED: 0,
    }


def test_local_scan_does_not_need_a_token(repo, tmp_path, monkeypatch, capsys):
    fake = FakeScanLocal(_outcome(tmp_path, [NOT_REPRODUCED] * 3))
    monkeypatch.setattr("pry.cli.scan_local", fake)

    assert main(["scan", str(repo)]) == 0
    assert fake.calls[0][0] == str(repo)
    assert "UNVERIFIED" not in capsys.readouterr().out


def test_local_scan_forwards_out_timeout_and_port(repo, tmp_path, monkeypatch):
    fake = FakeScanLocal(_outcome(tmp_path, [NOT_REPRODUCED] * 3))
    monkeypatch.setattr("pry.cli.scan_local", fake)

    assert (
        main(
            [
                "scan",
                str(repo),
                "--out",
                str(tmp_path / "out"),
                "--timeout",
                "2.5",
                "--port",
                "3000",
            ]
        )
        == 0
    )
    assert fake.calls[0][1] == {
        "out": str(tmp_path / "out"),
        "timeout": 2.5,
        "port": 3000,
        "endpoints": [],
    }


def test_missing_local_path_is_unverified(monkeypatch, capsys):
    fake = FakeScanLocal(
        error=IntakeError(REPO_NOT_FOUND, "not a directory: ./nope")
    )
    monkeypatch.setattr("pry.cli.scan_local", fake)

    assert main(["scan", "./nope"]) == 2
    assert "UNVERIFIED: REPO_NOT_FOUND: not a directory: ./nope" in capsys.readouterr().out
    assert fake.calls[0][0] == "./nope"


@pytest.mark.parametrize("level", ["1", "2"])
def test_local_scan_rejects_higher_intensity(repo, tmp_path, monkeypatch, capsys, level):
    fake = FakeScanLocal(_outcome(tmp_path, [NOT_REPRODUCED] * 3))
    monkeypatch.setattr("pry.cli.scan_local", fake)

    assert main(["scan", str(repo), "--level", level]) == 2
    assert fake.calls == []
    assert "UNVERIFIED: INTENSITY_INSUFFICIENT" in capsys.readouterr().out


def test_local_scan_reports_intake_errors(monkeypatch, capsys):
    fake = FakeScanLocal(error=IntakeError(BUILD_FAILED, "npm ERR!"))
    monkeypatch.setattr("pry.cli.scan_local", fake)

    assert main(["scan", "./app"]) == 2
    out = capsys.readouterr().out
    assert "UNVERIFIED: BUILD_FAILED" in out
    assert "npm ERR!" in out


def test_local_scan_reports_probe_errors(monkeypatch, capsys):
    fake = FakeScanLocal(error=ProbeError("RESULTS_FAILED", "cannot write results"))
    monkeypatch.setattr("pry.cli.scan_local", fake)

    assert main(["scan", "./app"]) == 2
    out = capsys.readouterr().out
    assert "UNVERIFIED: RESULTS_FAILED" in out
    assert "cannot write results" in out


def test_local_scan_signing_failure_exits_two(monkeypatch, capsys):
    fake = FakeScanLocal(
        error=ProofError(
            PROOF_FAILED,
            "cannot sign findings: PROOF_KEY_INVALID: key file must contain "
            "exactly 32 bytes",
        )
    )
    monkeypatch.setattr("pry.cli.scan_local", fake)

    assert main(["scan", "./app"]) == 2
    out = capsys.readouterr().out
    assert "UNVERIFIED: PROOF_FAILED" in out
    assert "PROOF_KEY_INVALID" in out


def test_url_scan_with_valid_token_is_unverified(capsys):
    assert main(["scan", TARGET, "--token", _token()]) == 1
    assert "UNVERIFIED: PROBE_INCONCLUSIVE" in capsys.readouterr().out


def test_url_scan_without_token_is_rejected(capsys):
    assert main(["scan", TARGET]) == 2
    assert "UNVERIFIED" in capsys.readouterr().out


def test_url_scan_with_invalid_token_is_rejected(capsys):
    assert main(["scan", TARGET, "--token", "garbage"]) == 2
    assert "TOKEN_MALFORMED" in capsys.readouterr().out


def test_url_scan_json_prints_unverified_object(capsys):
    assert main(["scan", TARGET, "--token", _token(), "--json"]) == 1

    data = json.loads(capsys.readouterr().out)
    assert data == {
        "status": "unverified",
        "cause": "PROBE_INCONCLUSIVE",
        "message": "probe suite not implemented",
    }


def test_url_with_path_is_not_treated_as_local(monkeypatch, capsys):
    fake = FakeScanLocal()
    monkeypatch.setattr("pry.cli.scan_local", fake)

    assert main(["scan", TARGET + "/app"]) == 2
    assert fake.calls == []
    assert "UNVERIFIED" in capsys.readouterr().out


def test_local_scan_forwards_repeatable_endpoints(
    repo, tmp_path, monkeypatch
):
    fake = FakeScanLocal(
        _outcome(
            tmp_path,
            [NOT_REPRODUCED] * 3,
            extra=[
                _endpoint_result("/api/users"),
                _endpoint_result("/api/admin", NOT_REPRODUCED),
            ],
        )
    )
    monkeypatch.setattr("pry.cli.scan_local", fake)

    assert (
        main(
            [
                "scan",
                str(repo),
                "--endpoint",
                "/api/users",
                "--endpoint",
                "/api/admin",
            ]
        )
        == 1
    )
    assert fake.calls[0][1]["endpoints"] == ["/api/users", "/api/admin"]


def test_local_scan_human_output_includes_the_endpoint_result(
    repo, tmp_path, monkeypatch, capsys
):
    fake = FakeScanLocal(
        _outcome(
            tmp_path,
            [NOT_REPRODUCED] * 3,
            extra=[_endpoint_result("/api/users", EXPOSED)],
        )
    )
    monkeypatch.setattr("pry.cli.scan_local", fake)

    assert main(["scan", str(repo), "--endpoint", "/api/users"]) == 1

    out = capsys.readouterr().out
    assert "unauth: EXPOSED" in out
    assert "/api/users" in out


def test_local_scan_json_includes_the_endpoint_result(
    repo, tmp_path, monkeypatch, capsys
):
    fake = FakeScanLocal(
        _outcome(
            tmp_path,
            [NOT_REPRODUCED] * 3,
            extra=[_endpoint_result("/api/users", EXPOSED)],
        )
    )
    monkeypatch.setattr("pry.cli.scan_local", fake)

    assert (
        main(["scan", str(repo), "--endpoint", "/api/users", "--json"]) == 1
    )

    data = json.loads(capsys.readouterr().out)
    assert [entry["probe"] for entry in data["results"]] == [
        "cors",
        "errors",
        "secrets",
        "unauth",
    ]
    assert data["results"][-1]["request"]["url"].endswith("/api/users")
    assert data["summary"] == {
        EXPOSED: 1,
        NOT_REPRODUCED: 3,
        UNVERIFIED: 0,
    }


def test_local_scan_exits_zero_when_the_endpoint_is_not_exposed(
    repo, tmp_path, monkeypatch, capsys
):
    fake = FakeScanLocal(
        _outcome(
            tmp_path,
            [NOT_REPRODUCED] * 3,
            extra=[_endpoint_result("/api/private", NOT_REPRODUCED)],
        )
    )
    monkeypatch.setattr("pry.cli.scan_local", fake)

    assert main(["scan", str(repo), "--endpoint", "/api/private"]) == 0
    assert "unauth: NOT_REPRODUCED" in capsys.readouterr().out


@pytest.mark.parametrize(
    "bad",
    [
        "http://evil.invalid",
        "https://evil.invalid/api",
        "//evil.invalid",
        "/api users",
        "api/users",
        "",
        "/" + "a" * 2048,
    ],
)
def test_local_scan_rejects_invalid_endpoints_before_scanning(
    repo, monkeypatch, capsys, bad
):
    fake = FakeScanLocal()
    monkeypatch.setattr("pry.cli.scan_local", fake)

    assert (
        main(
            [
                "scan",
                str(repo),
                "--endpoint",
                "/api/users",
                "--endpoint",
                bad,
            ]
        )
        == 2
    )

    assert fake.calls == []
    assert "UNVERIFIED: INVALID_ENDPOINT" in capsys.readouterr().out
