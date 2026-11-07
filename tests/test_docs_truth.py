"""AT15: the tracked docs must not claim more than the code does."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _read(relative):
    return (ROOT / relative).read_text(encoding="utf-8")


def test_readme_has_no_false_p1_completion_claim():
    text = _read("README.md")
    assert "Ownership verification (completed)" not in text
    assert "P1 ownership gate implemented" in text
    assert "Account Linking" not in text


def test_old_implementation_summary_is_superseded():
    text = _read("docs/planning/ownership-verification/IMPLEMENTATION_SUMMARY.md")
    assert "Superseded" in text
    assert "Status: Complete" not in text


def test_old_prd_is_marked_superseded():
    text = _read("docs/planning/ownership-verification/prd.md")
    assert "Superseded" in text


def test_capability_roadmap_is_honest():
    text = _read("docs/technical/CAPABILITY_ROADMAP.md")
    assert "Nothing is built yet" not in text
    assert "P1 ownership gate implemented" in text


def test_architecture_is_honest():
    text = _read("docs/technical/ARCHITECTURE.md")
    assert "Nothing is implemented yet" not in text
    assert "P1 is implemented" in text


def test_claude_status_is_honest():
    text = _read("CLAUDE.md")
    assert "day zero" not in text
    assert "P1 ownership gate implemented" in text


def test_readme_p2_is_honest():
    text = _read("README.md")
    assert "P2 local intake implemented" in text
    assert "Docker is required" in text
    assert "not a kernel-level security boundary" in text


def test_claude_p2_status():
    text = _read("CLAUDE.md")
    assert "P2 local intake implemented" in text


def test_capability_roadmap_p2_status():
    text = _read("docs/technical/CAPABILITY_ROADMAP.md")
    assert "P2 local intake implemented" in text


def test_architecture_p2_status():
    text = _read("docs/technical/ARCHITECTURE.md")
    assert "P2 local intake" in text


def test_ethics_gate_exists():
    text = _read("ETHICS.md")
    assert "EXPOSED" in text
    assert "NOT_REPRODUCED" in text
    assert "UNVERIFIED" in text
    assert "SAFE" in text
    assert "SECURE" in text


def test_readme_p3_is_honest():
    text = " ".join(_read("README.md").split())
    assert "P3 read-only floor probes implemented" in text
    assert "ETHICS.md" in text
    assert "missing-auth declarations" in text


def test_claude_p3_status():
    text = " ".join(_read("CLAUDE.md").split())
    assert "P3 read-only probes implemented" in text


def test_capability_roadmap_p3_status():
    text = _read("docs/technical/CAPABILITY_ROADMAP.md")
    assert "P3 read-only probe slice implemented" in text


def test_architecture_p3_status():
    text = " ".join(_read("docs/technical/ARCHITECTURE.md").split())
    assert "P3 read-only probes are implemented" in text


def test_readme_unauth_is_honest():
    text = " ".join(_read("README.md").split())
    assert "Unauthenticated endpoints" in text
    assert "--endpoint" in text
    assert "declared" in text


def test_claude_unauth_status():
    text = " ".join(_read("CLAUDE.md").split())
    assert "missing-auth declarations" in text
    assert "--endpoint" in text


def test_capability_roadmap_unauth_status():
    text = _read("docs/technical/CAPABILITY_ROADMAP.md")
    assert "declared unauthenticated endpoints" in text


def test_architecture_unauth_status():
    text = " ".join(_read("docs/technical/ARCHITECTURE.md").split())
    assert "declared unauth endpoints" in text


def test_readme_p5_is_honest():
    text = " ".join(_read("README.md").split())
    assert "Signed Proof Bundles (P5 read-only slice)" in text
    assert "verify-proof" in text
    assert "Ed25519" in text
    assert "fingerprint" in text


def test_claude_p5_status():
    text = " ".join(_read("CLAUDE.md").split())
    assert "P5 read-only signed proof bundles" in text


def test_capability_roadmap_p5_status():
    text = _read("docs/technical/CAPABILITY_ROADMAP.md")
    assert "P5 read-only signed bundles" in text


def test_architecture_p5_status():
    text = " ".join(_read("docs/technical/ARCHITECTURE.md").split())
    assert "P5 read-only signed bundles" in text


def test_readme_p6_is_honest():
    text = " ".join(_read("README.md").split())
    assert "Findings Report and Corpus (P6 read-only slice)" in text
    assert "pry report" in text
    assert "corpus" in text
    assert "no upload" in text.lower()


def test_claude_p6_status():
    text = " ".join(_read("CLAUDE.md").split())
    assert "P6 local findings report and corpus" in text


def test_capability_roadmap_p6_status():
    text = " ".join(_read("docs/technical/CAPABILITY_ROADMAP.md").split())
    assert "P6 local report/corpus" in text


def test_architecture_p6_status():
    text = " ".join(_read("docs/technical/ARCHITECTURE.md").split())
    assert "P6 local report/corpus" in text


def test_readme_live_readonly_is_honest():
    text = " ".join(_read("README.md").split())
    assert "Live Read-Only Scans" in text
    assert "P1 token" in text
    assert "GET-only" in text
    assert "4–6" in text


def test_claude_live_status():
    text = " ".join(_read("CLAUDE.md").split())
    assert "live read-only scans implemented" in text


def test_capability_roadmap_live_status():
    text = " ".join(_read("docs/technical/CAPABILITY_ROADMAP.md").split())
    assert "live read-only scans implemented" in text


def test_architecture_live_status():
    text = " ".join(_read("docs/technical/ARCHITECTURE.md").split())
    assert "Live read-only scans run from the host" in text
