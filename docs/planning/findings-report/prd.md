# PRD — Findings Report and Corpus (P6 read-only local slice)

- **Status:** Merged to `master` (2026-11-08). Local HTML report and JSONL corpus implemented;
  hosted/public reports, P4, live URL, and the remaining P3 checks are deferred.
- **Owner:** aliz
- **Slug:** `findings-report`
- **Capability:** P6 read-only local slice

## Problem Statement

Pry writes `results.json` and signed proof bundles, but the app owner has no readable artifact
to review or share. A JSON file and a directory of bundles are evidence, not a report. P6 must
turn a run into a self-contained report and bank the findings locally.

This slice is local-only. No upload, no hosted report, no public sharing. The report repeats
the no-secure-claim and deferred-checks caveats and shows each proof's fingerprint/validity.

## Goals & Success Metrics

1. `pry report RUN_DIR` writes a self-contained HTML report; `pry scan ./app --report` does it
   automatically.
2. Every finding shows probe, verdict, evidence, request/response, and proof fingerprint with
   VALID/INVALID.
3. The report is HTML-injection safe; all values are escaped; no external assets/JS.
4. The corpus appends one JSONL line per finding at 0600; a corpus failure is a warning, not a
   scan failure.
5. Missing/invalid run files produce a named error, not a traceback.
6. No "secure" claim; a safe scan report says `NOT_REPRODUCED`, never "safe."

## Requirements

### Must-have

| ID | Requirement |
|---|---|
| M1 | Corpus: `~/.pry/corpus.jsonl` (`PRY_CORPUS` override), 0600 dir/file, one JSON line per finding with created_at, sandbox_id, target, kind, probe, verdict, cause, proof, fingerprint. |
| M2 | `pry report RUN_DIR [--out PATH] [--json]`; default `RUN_DIR/report.html`, 0600, atomic. |
| M3 | Load `snapshot.json` + `results.json`; validate; for each result with a proof, load/verify and record fingerprint + VALID/INVALID; invalid proofs are shown, not hidden. |
| M4 | HTML: target basename/kind/commit/dirty/snapshot id, counts, per-finding evidence/request/response, proof fingerprint/status, no-secure/deferred note. |
| M5 | Escape every dynamic value with `html.escape`; no external CSS/JS/assets; no upload. |
| M6 | `pry scan ./app --report` writes the report and prints the path; the human/JSON scan output stays valid. |
| M7 | Corpus append after results/proofs; failure sets a warning on the CLI, not a failed scan. |
| M8 | Missing/invalid snapshot/results → `REPORT_MISSING`/`REPORT_MALFORMED`, exit 1/2, no traceback. |
| M9 | Tests: corpus, report load/render/escaping, invalid proof, missing files, CLI, Docker. |
| M10 | Docs state local-only reports, no upload, no secure claim, and what is deferred. |

### Should-have

- `pry report --json` metadata.
- A corpus reader command/future corpus report.
- Report title/timestamp from the snapshot.

## Technical Considerations

- No new dependencies; use `html`, `json`, `pathlib`, `os`.
- The report is a view over the run dir. The proof bundles are signed; the report is not.
- Proof paths in `results.json` may be absolute or relative; resolve relative to the run dir
  first, then the cwd.
- The report uses the already-redacted results; it must not add raw secrets.
- HTML is a single file with inline CSS; no JavaScript. All dynamic text escaped.
- Corpus append is append-only JSONL; no dedupe in this slice. Each scan run is distinct.
- A corpus write failure is a warning in `ScanOutcome.corpus_error`; the CLI prints it and
  still returns the scan verdict.

## Risks & Open Questions

| Risk | Severity | Mitigation |
|---|---|---|
| **XSS** in evidence/headers/body. | High/High | `html.escape` everything; test `<script>`; no JS. |
| **Secrets/PII** in the report. | Med/High | Use the redacted results; local 0600; no upload; docs. |
| **Invalid proof** shown as verified. | High/High | Verify each bundle; show INVALID and the reason. |
| **Corpus growth** unbounded. | Low/Med | Append-only; future rotation; local only. |
| **Report reads a moved run dir** and proof paths break. | Med/Med | Resolve relative to run dir; mark missing proof as INVALID/UNSIGNED. |
| **"Report" read as certification.** | High/High | Explicit no-secure/no-absence disclaimer in the report. |

**Hard question:** is a local HTML file enough for the owner to act on, or does P6 need a
hosted/shareable service? This slice says local first; hosting is a monetization experiment,
not a requirement for the proof.

## Out of Scope

- Hosted reports, public links, email, PDF.
- P4, live URL, IDOR/DB rules, remaining P3.
- Report signing (the bundles are signed).
- Uploading reports/proofs by default.

## Acceptance Tests

| ID | Test | Expected |
|---|---|---|
| AT1 | Corpus append | one JSONL line per finding, 0600 |
| AT2 | Report from a vulnerable run | four findings, four fingerprints, VALID |
| AT3 | Safe run report | zero EXPOSED, no fingerprints |
| AT4 | Tampered proof | INVALID in the report |
| AT5 | `<script>` in evidence/body | escaped, not executable |
| AT6 | Missing snapshot/results | named error, no traceback |
| AT7 | `pry report` CLI | path printed, exit 0 |
| AT8 | `pry scan --report` | report written, scan verdict/exit preserved |
| AT9 | Corpus failure | warning, scan still succeeds |
| AT10 | Default suite | offline; Docker opt-in |

## Self-Critique

- 🟡 **Local-only report** does not solve sharing; it makes the owner's review possible.
- 🟡 **HTML escaping is the critical surface**; tests must include script/attribute injection.
- 🟢 **The report reuses the signed bundles and verifies them**, so it cannot silently upgrade
  an invalid proof to verified.
