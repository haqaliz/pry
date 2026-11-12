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
    assert "up to 12 requests" in text


def test_claude_live_status():
    text = " ".join(_read("CLAUDE.md").split())
    assert "live read-only scans implemented" in text


def test_capability_roadmap_live_status():
    text = " ".join(_read("docs/technical/CAPABILITY_ROADMAP.md").split())
    assert "live read-only scans implemented" in text


def test_architecture_live_status():
    text = " ".join(_read("docs/technical/ARCHITECTURE.md").split())
    assert "Live read-only scans run from the host" in text


def test_readme_idor_is_honest():
    text = " ".join(_read("README.md").split())
    assert "Configured IDOR Checks (Live)" in text
    assert "--idor-config" in text
    assert "0600" in text
    assert "redact" in text.lower()


def test_claude_idor_status():
    text = " ".join(_read("CLAUDE.md").split()).lower()
    assert "configured live idor" in text


def test_capability_roadmap_idor_status():
    text = " ".join(_read("docs/technical/CAPABILITY_ROADMAP.md").split()).lower()
    assert "configured live idor" in text


def test_architecture_idor_status():
    text = " ".join(_read("docs/technical/ARCHITECTURE.md").split()).lower()
    assert "configured live idor" in text


def test_readme_ssrf_is_honest():
    text = " ".join(_read("README.md").split())
    assert "SSRF (Level 1, local and live)" in text
    assert "--level 1" in text
    assert "--confirm" in text
    assert "--ssrf-endpoint" in text
    assert "--ssrf-callback-url" in text
    assert "200 only after" in text
    assert "different origin" in text


def test_roadmap_ssrf_status():
    text = " ".join(_read("docs/ROADMAP.md").split()).lower()
    assert "local/live level 1 ssrf" in text


def test_claude_ssrf_status():
    text = " ".join(_read("CLAUDE.md").split()).lower()
    assert "local and live level 1 ssrf" in text


def test_capability_roadmap_ssrf_status():
    text = " ".join(_read("docs/technical/CAPABILITY_ROADMAP.md").split()).lower()
    assert "local and live level 1 ssrf" in text


def test_architecture_ssrf_status():
    text = " ".join(_read("docs/technical/ARCHITECTURE.md").split()).lower()
    assert "ssrf level 1 is callback-proven" in text


def test_readme_rate_limit_is_honest():
    text = " ".join(_read("README.md").split())
    assert "Rate-Limit Observation (Level 1, local and live)" in text
    assert "--rate-limit-endpoint" in text
    assert "not a verdict" in text
    assert "OBSERVED" in text
    assert "Live: 1–5 GETs, 0.5s apart" in text
    assert "stop on the first 429/503" in text


def test_claude_rate_limit_status():
    text = " ".join(_read("CLAUDE.md").split()).lower()
    assert "live rate-limit" in text
    assert "capped at five gets" in text


def test_capability_roadmap_rate_limit_status():
    text = " ".join(_read("docs/technical/CAPABILITY_ROADMAP.md").split()).lower()
    assert "rate-limit observation" in text


def test_architecture_rate_limit_status():
    text = " ".join(_read("docs/technical/ARCHITECTURE.md").split()).lower()
    assert "rate-limit is an observation" in text


def test_readme_local_idor_is_honest():
    text = " ".join(_read("README.md").split())
    assert "Local IDOR" in text
    assert "read-only at `/pry-config/idor.json`" in text
    assert "temp copy" in text
    assert "No discovery" in text


def test_claude_local_idor_status():
    text = " ".join(_read("CLAUDE.md").split()).lower()
    assert "local idor implemented" in text


def test_capability_roadmap_local_idor_status():
    text = " ".join(_read("docs/technical/CAPABILITY_ROADMAP.md").split()).lower()
    assert "local idor implemented" in text


def test_architecture_local_idor_status():
    text = " ".join(_read("docs/technical/ARCHITECTURE.md").split()).lower()
    assert "local idor" in text


def test_readme_header_observations_are_honest():
    text = " ".join(_read("README.md").split())
    assert "Response Header Observations" in text
    assert "not a verdict" in text
    assert "HTTPS only" in text
    assert "unsigned observation" in text


def test_claude_header_observation_status():
    text = " ".join(_read("CLAUDE.md").split()).lower()
    assert "response header observations implemented" in text


def test_capability_roadmap_header_observation_status():
    text = " ".join(_read("docs/technical/CAPABILITY_ROADMAP.md").split()).lower()
    assert "header observations" in text


def test_architecture_header_observation_status():
    text = " ".join(_read("docs/technical/ARCHITECTURE.md").split()).lower()
    assert "response headers are an observation" in text


def test_readme_database_files_are_honest():
    text = " ".join(_read("README.md").split())
    assert "Exposed Database Files" in text
    assert "/data.db" in text
    assert "signature excerpt" in text
    assert "rows are never kept" in text
    assert "Provider rule checks" in text


def test_claude_database_file_status():
    text = " ".join(_read("CLAUDE.md").split()).lower()
    assert "exposed database file checks implemented" in text


def test_capability_roadmap_database_file_status():
    text = " ".join(_read("docs/technical/CAPABILITY_ROADMAP.md").split()).lower()
    assert "served database file checks" in text


def test_architecture_database_file_status():
    text = " ".join(_read("docs/technical/ARCHITECTURE.md").split()).lower()
    assert "served database files are signature-proven" in text


def test_readme_level2_write_is_honest():
    text = " ".join(_read("README.md").split())
    assert "Level 2 Write Confirmation (local and live)" in text
    assert "{{marker}}" in text
    assert "verification pair" in text
    assert "--confirm-live-write" in text
    assert "there is no rollback" in text
    assert "staging" in text


def test_claude_level2_write_status():
    text = " ".join(_read("CLAUDE.md").split()).lower()
    assert "local and live level 2 write confirmation implemented" in text


def test_capability_roadmap_level2_write_status():
    text = " ".join(_read("docs/technical/CAPABILITY_ROADMAP.md").split()).lower()
    assert "local and live level 2 write confirmation implemented" in text


def test_architecture_level2_write_status():
    text = " ".join(_read("docs/technical/ARCHITECTURE.md").split()).lower()
    assert "level 2 writes are marker-verified" in text
    assert "--confirm-live-write" in text


def test_roadmap_level2_write_status():
    text = " ".join(_read("docs/ROADMAP.md").split())
    assert "Level 2 write confirmation implemented local and live" in text


def test_readme_live_replay_is_honest():
    text = " ".join(_read("README.md").split())
    assert "Live Replay" in text
    assert "pry replay" in text
    assert "status-only" in text
    assert "MATCH" in text
    assert "Local and write proofs are refused" in text


def test_claude_live_replay_status():
    text = " ".join(_read("CLAUDE.md").split()).lower()
    assert "live read-only replay" in text


def test_capability_roadmap_live_replay_status():
    text = " ".join(_read("docs/technical/CAPABILITY_ROADMAP.md").split()).lower()
    assert "live read-only replay implemented" in text


def test_architecture_live_replay_status():
    text = " ".join(_read("docs/technical/ARCHITECTURE.md").split()).lower()
    assert "live replay is status-only" in text


def test_roadmap_live_replay_status():
    text = " ".join(_read("docs/ROADMAP.md").split()).lower()
    assert "live read-only replay is implemented" in text


def test_readme_provider_database_is_honest():
    text = " ".join(_read("README.md").split())
    assert "Provider Database Rules (Firebase / Supabase)" in text
    assert "--confirm-marker" in text
    assert "control attestation" in text
    assert "apikey" in text
    assert "4 KiB" in text


def test_claude_provider_database_status():
    text = " ".join(_read("CLAUDE.md").split()).lower()
    assert "provider database/open-rule checks implemented" in text


def test_capability_roadmap_provider_database_status():
    text = " ".join(_read("docs/technical/CAPABILITY_ROADMAP.md").split()).lower()
    assert "provider database marker checks" in text


def test_architecture_provider_database_status():
    text = " ".join(_read("docs/technical/ARCHITECTURE.md").split()).lower()
    assert "provider database checks use a marker" in text


def test_roadmap_provider_database_status():
    text = " ".join(_read("docs/ROADMAP.md").split()).lower()
    assert "provider database/open-rule checks are implemented" in text


def test_readme_release_install_is_honest():
    text = " ".join(_read("README.md").split())
    assert "pry-scanner" in text
    assert "v0.1.0" in text
    assert "CI / Pre-Publish" in text
    assert "haqaliz/pry@v0.1.0" in text


def test_changelog_records_the_release():
    text = " ".join(_read("CHANGELOG.md").split())
    assert "## [0.1.0] - 2026-11-12" in text
    assert "pry-scanner" in text
    assert "Not in 0.1.0" in text


def test_security_policy_uses_private_reporting():
    text = " ".join(_read("SECURITY.md").split())
    assert "GitHub private vulnerability reporting" in text
    assert "/security/advisories/new" in text
    assert "Do not open a public issue" in text


def test_release_checklist_names_the_distribution():
    text = " ".join(_read("docs/RELEASE.md").split())
    assert "`pry-scanner`" in text
    assert "PYPI_PUBLISH" in text
    assert "git tag -a vX.Y.Z" in text


def test_readme_public_sections_are_present():
    text = " ".join(_read("README.md").split())
    assert "Start here" in text
    assert "What Pry never claims" in text
    assert "At a glance" in text
    assert "pry-scanner" in text
    assert "actions/workflows/ci.yml/badge.svg" in text


def test_contributing_is_honest():
    text = " ".join(_read("CONTRIBUTING.md").split())
    assert "test-first" in text
    assert "Docker integration tests are opt-in" in text
    assert '"SAFE" or "SECURE" verdict' in text
    assert "Pattern-matching as a verdict" in text


def test_code_of_conduct_exists():
    text = " ".join(_read("CODE_OF_CONDUCT.md").split())
    assert "harassment-free" in text
    assert "Contributor Covenant" in text


def test_public_roadmap_has_next_and_not_doing():
    text = " ".join(_read("docs/ROADMAP.md").split())
    assert "Status at v0.1.0" in text
    assert "Next." in text
    assert "Deliberately not doing" in text
    assert "Owner-approved discovery" in text


def test_docs_index_links_the_public_docs():
    text = " ".join(_read("docs/README.md").split())
    assert "ARCHITECTURE" in text
    assert "CONTRIBUTING" in text
    assert "SECURITY" in text
    assert "CASE_STUDY_TEMPLATE" in text


def test_issue_and_pr_templates_exist():
    for relative in (
        ".github/ISSUE_TEMPLATE/bug_report.yml",
        ".github/ISSUE_TEMPLATE/feature_request.yml",
        ".github/ISSUE_TEMPLATE/config.yml",
        ".github/PULL_REQUEST_TEMPLATE.md",
    ):
        assert (ROOT / relative).is_file()


def test_readme_faq_is_honest():
    text = " ".join(_read("README.md").split())
    assert "## FAQ" in text
    assert "Is a clean scan" in text
    assert "No. Pry has no safe verdict." in text
    assert "Does it upload my code or data?" in text
    assert "No. The sandbox and proofs are local" in text
    assert "Does it discover endpoints?" in text
    assert "Discovery" in text


def test_public_assets_exist():
    for relative in (
        "assets/pry-logo.svg",
        "assets/pry-mark.svg",
        "assets/pry-demo.gif",
        "assets/pry-demo.mp4",
        "assets/pry-demo-scan.png",
        "assets/social-card.png",
    ):
        assert (ROOT / relative).is_file()
        assert (ROOT / relative).stat().st_size > 0


def test_readme_uses_the_logo_and_demo():
    text = _read("README.md")
    assert "assets/pry-mark.svg" in text
    assert "assets/pry-demo.gif" in text
    assert "haqaliz.github.io/pry" in text


def test_site_references_only_local_assets():
    text = " ".join(_read("site/index.html").split())
    assert "assets/pry-mark.svg" in text
    assert "assets/pry-demo.mp4" in text
    assert "assets/pry-demo-scan.png" in text
    assert "https://haqaliz.github.io/pry/assets/social-card.png" in text


def test_pages_workflow_exists():
    text = _read(".github/workflows/pages.yml")
    assert "actions/deploy-pages" in text
    assert "site/index.html" in text
    assert "assets/pry-demo.mp4" in text
