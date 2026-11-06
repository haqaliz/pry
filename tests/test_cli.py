"""CLI and ownership gate tests (AT9-AT13)."""

import pytest

from pry.cli import main, run_scan
from pry.own.errors import OwnershipError
from pry.own.target import normalize_target
from pry.own.tokens import TokenSigner

TARGET = "https://example.com"
NONCE = "A" * 43


@pytest.fixture(autouse=True)
def temp_key(tmp_path, monkeypatch):
    monkeypatch.setenv("PRY_KEY_FILE", str(tmp_path / "ownership.key"))


def _token(target=TARGET, now=None):
    return TokenSigner().issue(normalize_target(target), "dns_txt", now=now)


def test_help_exits_zero():
    with pytest.raises(SystemExit) as exc:
        main(["--help"])
    assert exc.value.code == 0


def test_no_command_prints_help(capsys):
    assert main([]) == 1
    assert "usage:" in capsys.readouterr().out


def test_verify_without_challenge_prints_dns_instructions(capsys):
    assert main(["verify-ownership", TARGET, "--method", "dns"]) == 1
    out = capsys.readouterr().out
    assert "_pry.example.com" in out
    assert "pry-verify=" in out
    assert "Token:" not in out


def test_verify_without_challenge_prints_well_known_instructions(capsys):
    assert main(["verify-ownership", TARGET, "--method", "well-known"]) == 1
    out = capsys.readouterr().out
    assert "https://example.com/.well-known/pry-ownership.txt" in out
    assert "pry-verify=" in out


def test_verify_success_prints_token(monkeypatch, capsys):
    monkeypatch.setattr("pry.cli.verify_target", lambda *a, **k: "pry1.test.token")

    assert main(
        ["verify-ownership", TARGET, "--method", "dns", "--challenge", NONCE]
    ) == 0
    out = capsys.readouterr().out
    assert "pry1.test.token" in out
    assert "Ownership verified" in out


def test_verify_success_json(monkeypatch, capsys):
    monkeypatch.setattr("pry.cli.verify_target", lambda *a, **k: "pry1.test.token")

    assert main(
        [
            "verify-ownership",
            TARGET,
            "--method",
            "dns",
            "--challenge",
            NONCE,
            "--json",
        ]
    ) == 0
    out = capsys.readouterr().out
    assert '"status": "verified"' in out
    assert '"token": "pry1.test.token"' in out


def test_verify_failure_returns_one_and_names_cause(monkeypatch, capsys):
    def fail(*args, **kwargs):
        raise OwnershipError("DNS_MISMATCH", "no match")

    monkeypatch.setattr("pry.cli.verify_target", fail)

    assert main(
        ["verify-ownership", TARGET, "--method", "dns", "--challenge", NONCE]
    ) == 1
    out = capsys.readouterr().out
    assert "UNVERIFIED" in out
    assert "DNS_MISMATCH" in out


def test_verify_bad_challenge_is_usage_error(capsys):
    assert main(["verify-ownership", TARGET, "--method", "dns", "--challenge", "short"]) == 2
    assert "BAD_CHALLENGE" in capsys.readouterr().out


def test_verify_bad_target_is_usage_error(capsys):
    assert main(["verify-ownership", "ftp://example.com", "--method", "dns"]) == 2
    assert "UNSUPPORTED_TARGET" in capsys.readouterr().out


def test_verify_requires_method():
    with pytest.raises(SystemExit) as exc:
        main(["verify-ownership", TARGET])
    assert exc.value.code == 2


def test_scan_without_token_is_rejected(capsys):
    assert main(["scan", TARGET]) == 2
    assert "UNVERIFIED" in capsys.readouterr().out


def test_scan_without_token_does_not_create_a_key(tmp_path, monkeypatch):
    key_path = tmp_path / "should-not-exist"
    monkeypatch.setenv("PRY_KEY_FILE", str(key_path))

    assert main(["scan", TARGET]) == 2
    assert not key_path.exists()


def test_scan_empty_token_is_rejected(capsys):
    assert main(["scan", TARGET, "--token", ""]) == 2
    assert "UNVERIFIED" in capsys.readouterr().out


def test_scan_garbage_token_is_rejected(capsys):
    assert main(["scan", TARGET, "--token", "garbage"]) == 2
    assert "TOKEN_MALFORMED" in capsys.readouterr().out


def test_scan_wrong_target_token_is_rejected(capsys):
    token = _token("https://other.example")

    assert main(["scan", TARGET, "--token", token]) == 2
    assert "TOKEN_TARGET_MISMATCH" in capsys.readouterr().out


def test_scan_expired_token_is_rejected(capsys):
    token = _token(now=0)

    assert main(["scan", TARGET, "--token", token]) == 2
    assert "TOKEN_EXPIRED" in capsys.readouterr().out


def test_scan_never_runs_probe_without_a_valid_token(monkeypatch):
    called = []
    monkeypatch.setattr("pry.cli.run_scan", lambda proof: called.append(proof) or 0)

    assert main(["scan", TARGET, "--token", "garbage"]) == 2
    assert called == []


def test_scan_valid_token_calls_run_scan(monkeypatch):
    token = _token()
    seen = []
    monkeypatch.setattr("pry.cli.run_scan", lambda proof: seen.append(proof) or 1)

    assert main(["scan", TARGET, "--token", token]) == 1
    assert len(seen) == 1
    assert seen[0].target == TARGET


def test_run_scan_reports_unverified(capsys):
    token = _token()
    proof = TokenSigner().validate(token, normalize_target(TARGET))

    assert run_scan(proof) == 1
    out = capsys.readouterr().out
    assert "UNVERIFIED" in out
    assert "PROBE_INCONCLUSIVE" in out


@pytest.mark.parametrize("level", ["1", "2"])
def test_scan_rejects_higher_intensity(level, monkeypatch, capsys):
    token = _token()
    called = []
    monkeypatch.setattr("pry.cli.run_scan", lambda proof: called.append(proof) or 0)

    assert main(["scan", TARGET, "--token", token, "--level", level]) == 2
    assert called == []
    assert "INTENSITY_INSUFFICIENT" in capsys.readouterr().out


def test_scan_reads_token_file(tmp_path, monkeypatch):
    token = _token()
    path = tmp_path / "token"
    path.write_text(token)
    seen = []
    monkeypatch.setattr("pry.cli.run_scan", lambda proof: seen.append(proof) or 1)

    assert main(["scan", TARGET, "--token-file", str(path)]) == 1
    assert len(seen) == 1


def test_scan_rejects_both_token_sources(tmp_path, capsys):
    path = tmp_path / "token"
    path.write_text("x")

    assert main(["scan", TARGET, "--token", "x", "--token-file", str(path)]) == 2
    assert "UNVERIFIED" in capsys.readouterr().out


def test_scan_missing_token_file_is_usage_error(tmp_path, capsys):
    assert main(["scan", TARGET, "--token-file", str(tmp_path / "nope")]) == 2
    assert "TOKEN_MALFORMED" in capsys.readouterr().out
