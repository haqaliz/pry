"""CLI local IDOR config tests (AT1, AT4, AT5, AT7).

The scan itself is faked: nothing here starts a container or opens a socket.
"""

import json
import os

import pytest

from pry.cli import main
from pry.probe.idor import IdorConfig
from pry.probe.results import EXPOSED, NOT_REPRODUCED, ProbeResult, summarize
from pry.probe.scan import ScanOutcome

SECRET_A = "cli-local-alice-secret"
SECRET_B = "cli-local-bob-secret"


def _payload(headers_a=None):
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


def _write_config(tmp_path, data=None, mode=0o600):
    path = tmp_path / "idor.json"
    payload = _payload() if data is None else data
    path.write_text(json.dumps(payload), encoding="utf-8")
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


def _outcome(tmp_path, verdicts, extra=None):
    results = [
        _result(probe, verdict)
        for probe, verdict in zip(("cors", "errors", "secrets"), verdicts)
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
    def __init__(self, outcome=None):
        self.outcome = outcome
        self.calls = []

    def __call__(self, path, **kwargs):
        self.calls.append((path, kwargs))
        return self.outcome


class FakeScanLive:
    def __init__(self):
        self.calls = []

    def __call__(self, url, token, **kwargs):
        self.calls.append((url, token, kwargs))


@pytest.fixture
def repo(tmp_path):
    path = tmp_path / "repo"
    path.mkdir()
    return path


def test_local_scan_forwards_a_valid_idor_config_without_confirm(
    repo, tmp_path, monkeypatch, capsys
):
    path = _write_config(tmp_path)
    fake = FakeScanLocal(
        _outcome(
            tmp_path,
            [NOT_REPRODUCED] * 3,
            extra=[_result("idor", NOT_REPRODUCED)],
        )
    )
    monkeypatch.setattr("pry.cli.scan_local", fake)

    assert main(["scan", str(repo), "--idor-config", str(path)]) == 0

    assert len(fake.calls) == 1
    _path, kwargs = fake.calls[0]
    config = kwargs["idor_config"]
    assert isinstance(config, IdorConfig)
    assert config.headers_a == {"Cookie": "sid=" + SECRET_A}
    assert config.headers_b == {"Cookie": "sid=" + SECRET_B}
    assert (config.object_a, config.object_b) == ("/api/orders/1", "/api/orders/2")
    out = capsys.readouterr().out
    assert "idor: NOT_REPRODUCED" in out
    assert "IDOR_REQUIRES_LIVE" not in out
    assert SECRET_A not in out
    assert SECRET_B not in out
    assert str(path) not in out


def test_local_scan_with_an_exposed_idor_config_exits_one(
    repo, tmp_path, monkeypatch, capsys
):
    path = _write_config(tmp_path)
    fake = FakeScanLocal(
        _outcome(
            tmp_path,
            [NOT_REPRODUCED] * 3,
            extra=[_result("idor", EXPOSED)],
        )
    )
    monkeypatch.setattr("pry.cli.scan_local", fake)

    assert main(["scan", str(repo), "--idor-config", str(path)]) == 1
    assert "idor: EXPOSED" in capsys.readouterr().out


def test_level_one_accepts_the_idor_config_itself(
    repo, tmp_path, monkeypatch, capsys
):
    path = _write_config(tmp_path)
    fake = FakeScanLocal(
        _outcome(
            tmp_path,
            [NOT_REPRODUCED] * 3,
            extra=[_result("idor", NOT_REPRODUCED)],
        )
    )
    monkeypatch.setattr("pry.cli.scan_local", fake)

    assert (
        main(
            [
                "scan",
                str(repo),
                "--level",
                "1",
                "--confirm",
                "--idor-config",
                str(path),
            ]
        )
        == 0
    )

    _path, kwargs = fake.calls[0]
    assert kwargs["idor_config"] is not None
    assert "ssrf_config" not in kwargs
    assert "rate_limit_config" not in kwargs
    assert "LEVEL1_CHECK_REQUIRED" not in capsys.readouterr().out


@pytest.mark.parametrize("mode", [0o644, 0o640])
def test_local_scan_with_a_group_readable_idor_config_never_scans(
    repo, tmp_path, monkeypatch, capsys, mode
):
    path = _write_config(tmp_path, mode=mode)
    fake = FakeScanLocal()
    monkeypatch.setattr("pry.cli.scan_local", fake)

    assert main(["scan", str(repo), "--idor-config", str(path)]) == 2

    assert fake.calls == []
    out = capsys.readouterr().out
    assert "IDOR_CONFIG_INVALID" in out
    assert str(path) not in out
    assert SECRET_A not in out
    assert SECRET_B not in out


@pytest.mark.parametrize("data", ["{not json", "[]"])
def test_local_scan_with_a_malformed_idor_config_never_scans(
    repo, tmp_path, monkeypatch, capsys, data
):
    path = tmp_path / "idor.json"
    path.write_text(data, encoding="utf-8")
    os.chmod(str(path), 0o600)
    fake = FakeScanLocal()
    monkeypatch.setattr("pry.cli.scan_local", fake)

    assert main(["scan", str(repo), "--idor-config", str(path)]) == 2

    assert fake.calls == []
    out = capsys.readouterr().out
    assert "IDOR_CONFIG_INVALID" in out
    assert str(path) not in out


def test_local_scan_with_a_missing_idor_config_never_scans(
    repo, tmp_path, monkeypatch, capsys
):
    path = tmp_path / "missing.json"
    fake = FakeScanLocal()
    monkeypatch.setattr("pry.cli.scan_local", fake)

    assert main(["scan", str(repo), "--idor-config", str(path)]) == 2

    assert fake.calls == []
    out = capsys.readouterr().out
    assert "IDOR_CONFIG_INVALID" in out
    assert str(path) not in out


def test_local_scan_with_a_header_injection_in_the_idor_config_never_scans(
    repo, tmp_path, monkeypatch, capsys
):
    path = _write_config(
        tmp_path,
        _payload(headers_a={"Cookie": "sid=" + SECRET_A + "\r\nX-Injected: 1"}),
    )
    fake = FakeScanLocal()
    monkeypatch.setattr("pry.cli.scan_local", fake)

    assert main(["scan", str(repo), "--idor-config", str(path)]) == 2

    assert fake.calls == []
    out = capsys.readouterr().out
    assert "IDOR_CONFIG_INVALID" in out
    assert str(path) not in out
    assert SECRET_A not in out
