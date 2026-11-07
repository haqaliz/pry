# Findings Report and Corpus (P6 read-only local slice)

- **Type:** feat
- **Slug:** `findings-report`
- **Owner:** aliz
- **Source:** inline brief. No GitHub issue.
- **Capability:** P6 read-only local slice. Depends on P1–P3, P5 read-only signed bundles, and
  `ETHICS.md`.

## Brief

Pry now writes `results.json` and signed proof bundles, but the app owner has no readable
artifact. P6 must bank the findings and generate a self-contained report they can read and
share. This slice is local-only: HTML generated from a run directory, no upload, no hosted
service.

The report shows the target snapshot, the verdict counts, each probe's evidence and
request/response, and the proof fingerprint with a VALID/INVALID status. It repeats the
no-secure-claim and deferred-checks caveats. It uses the already-redacted results; it must not
introduce raw secrets.

## Current state

- Local scans write `snapshot.json`, `results.json`, and `proofs/<bundle_id>.json`.
- `pry verify-proof` verifies a bundle.
- There is no corpus and no report command.
- `ETHICS.md` is approved.

## Scope

1. Corpus: append one JSONL record per finding to `~/.pry/corpus.jsonl` (`PRY_CORPUS`
   override), 0600; record target, probe, verdict, cause, proof path, fingerprint, timestamp.
   A corpus write failure is a warning, not a scan failure.
2. `pry report RUN_DIR [--out PATH] [--json]`: load `snapshot.json`/`results.json`, verify each
   proof, render a self-contained HTML file (default `RUN_DIR/report.html`), 0600.
3. `pry scan ./app --report`: generate the report after a local scan and print its path.
4. Report content: target basename/kind/commit/dirty/snapshot id, counts, per-finding probe/
   verdict/evidence/request/response, proof fingerprint and validity, no-secure/deferred note.
5. Escape all report text (HTML injection safe); no external CSS/JS/assets; no upload.
6. Tests: corpus, report load/render/escaping, invalid proof, missing files, CLI, Docker.

## Out of scope

- Hosted reports, public sharing, PDF export, email.
- P4, live URL, IDOR/DB rules, remaining P3.
- Report signing (the proof bundles are signed; the report is a view).
- Uploading any report or proof by default.

## Acceptance criteria

- A vulnerable local scan writes a report with four findings and four proof fingerprints;
  each proof shows VALID.
- A safe scan writes a report with zero EXPOSED and no proof fingerprints.
- A tampered proof shows INVALID in the report; the report does not claim it is verified.
- `<script>` in evidence/body is escaped, not executable.
- Missing/invalid run files → a named error, no traceback.
- Corpus appends one line per finding; 0600; failure is a warning.
- Default suite offline; Docker tests opt-in.
- No "secure" claim in the report.
