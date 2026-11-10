"""Load a run directory, verify its proofs, and render safe local HTML."""

import html
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional
from urllib.parse import urlsplit

from pry.probe.results import RESULTS_FILE, VERDICTS
from pry.proof import ProofError, load_bundle, verify_bundle
from pry.report.corpus import (
    REPORT_FAILED,
    REPORT_MALFORMED,
    REPORT_MISSING,
    ReportError,
)

SNAPSHOT_FILE = "snapshot.json"
REPORT_FILE = "report.html"
VALID = "VALID"
INVALID = "INVALID"
UNSIGNED = "UNSIGNED"


@dataclass(frozen=True)
class Finding:
    probe: str
    verdict: str
    cause: Optional[str]
    evidence: str
    request: dict
    response: Optional[dict]
    proof: Optional[str]
    proof_status: Optional[str]
    fingerprint: Optional[str]
    proof_error: Optional[str]


@dataclass(frozen=True)
class Report:
    run_dir: Path
    snapshot: dict
    snapshot_id: str
    target: dict
    created_at: Optional[str]
    counts: dict
    findings: List[Finding]
    observations: List[dict]


def _malformed(message: str) -> ReportError:
    return ReportError(REPORT_MALFORMED, message)


def _read_json(path: Path, name: str) -> dict:
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        raise ReportError(REPORT_MISSING, "%s is missing: %s" % (name, path))
    except OSError as exc:
        raise ReportError(REPORT_FAILED, "cannot read %s: %s" % (name, exc))
    try:
        data = json.loads(text)
    except ValueError:
        raise _malformed("%s is not valid JSON" % name)
    if not isinstance(data, dict):
        raise _malformed("%s must be a JSON object" % name)
    return data


def _resolve_proof(run_dir: Path, proof: str) -> Path:
    path = Path(proof).expanduser()
    if path.is_absolute():
        return path
    candidate = run_dir / path
    if candidate.exists():
        return candidate
    return Path.cwd() / path


def _check_proof(run_dir: Path, proof: str):
    path = _resolve_proof(run_dir, proof)
    try:
        bundle = load_bundle(path)
        _payload, fingerprint = verify_bundle(bundle)
    except ProofError as exc:
        return INVALID, None, str(exc)
    return VALID, fingerprint, None


def _finding(run_dir: Path, index: int, entry) -> Finding:
    name = "result %d" % (index + 1)
    if not isinstance(entry, dict):
        raise _malformed("%s must be a JSON object" % name)
    probe = entry.get("probe")
    verdict = entry.get("verdict")
    if not isinstance(probe, str) or not probe:
        raise _malformed("%s must have a probe name" % name)
    if verdict not in VERDICTS:
        raise _malformed("%s has an unknown verdict" % name)
    evidence = entry.get("evidence", "")
    if not isinstance(evidence, str):
        raise _malformed("%s evidence must be a string" % name)
    request = entry.get("request")
    if not isinstance(request, dict):
        raise _malformed("%s request must be an object" % name)
    response = entry.get("response")
    if response is not None and not isinstance(response, dict):
        raise _malformed("%s response must be an object" % name)
    proof = entry.get("proof")
    if proof is not None and not isinstance(proof, str):
        raise _malformed("%s proof must be a string" % name)
    cause = entry.get("cause")
    if cause is not None and not isinstance(cause, str):
        raise _malformed("%s cause must be a string" % name)

    if proof:
        status, fingerprint, error = _check_proof(run_dir, proof)
    elif verdict == "EXPOSED":
        status, fingerprint, error = (
            UNSIGNED,
            None,
            "EXPOSED finding has no proof bundle",
        )
    else:
        status, fingerprint, error = None, None, None

    return Finding(
        probe=probe,
        verdict=verdict,
        cause=cause,
        evidence=evidence,
        request=request,
        response=response,
        proof=proof,
        proof_status=status,
        fingerprint=fingerprint,
        proof_error=error,
    )


def load_run(run_dir) -> Report:
    """Read and validate a run dir, verifying every attached proof bundle."""
    run_dir = Path(run_dir).expanduser()
    if not run_dir.is_dir():
        raise ReportError(
            REPORT_MISSING, "run directory is missing: %s" % run_dir
        )

    snapshot = _read_json(run_dir / SNAPSHOT_FILE, SNAPSHOT_FILE)
    data = _read_json(run_dir / RESULTS_FILE, RESULTS_FILE)

    target = snapshot.get("target")
    sandbox_id = snapshot.get("sandbox_id")
    if (
        not isinstance(target, dict)
        or not isinstance(target.get("path"), str)
        or not isinstance(target.get("kind"), str)
    ):
        raise _malformed(
            "%s must contain a target with path and kind" % SNAPSHOT_FILE
        )
    if not isinstance(sandbox_id, str) or not sandbox_id:
        raise _malformed("%s must contain a sandbox_id" % SNAPSHOT_FILE)

    entries = data.get("results")
    if not isinstance(entries, list):
        raise _malformed("%s must contain a results list" % RESULTS_FILE)
    created_at = data.get("created_at")
    if created_at is not None and not isinstance(created_at, str):
        raise _malformed("%s created_at must be a string" % RESULTS_FILE)
    observations = data.get("observations", [])
    if not isinstance(observations, list) or not all(
        isinstance(entry, dict) for entry in observations
    ):
        raise _malformed(
            "%s observations must be a list of objects" % RESULTS_FILE
        )

    counts = {verdict: 0 for verdict in VERDICTS}
    findings = []
    for index, entry in enumerate(entries):
        finding = _finding(run_dir, index, entry)
        counts[finding.verdict] += 1
        findings.append(finding)

    return Report(
        run_dir=run_dir,
        snapshot=snapshot,
        snapshot_id=sandbox_id,
        target=target,
        created_at=created_at,
        counts=counts,
        findings=findings,
        observations=observations,
    )


def _esc(value) -> str:
    return html.escape("" if value is None else str(value))


def _headers_text(headers) -> str:
    if not isinstance(headers, dict):
        return ""
    return "\n".join("%s: %s" % (name, value) for name, value in headers.items())


def _target_basename(path: str) -> str:
    if "://" in path:
        return urlsplit(path).hostname or path
    return Path(path).name or path


def _proof_html(finding: Finding) -> str:
    if finding.proof_status is None:
        return "<p>No proof bundle attached.</p>"
    rows = ["<dt>Status</dt><dd>%s</dd>" % _esc(finding.proof_status)]
    if finding.proof:
        rows.append(
            "<dt>Bundle</dt><dd>%s</dd>"
            % _esc(Path(finding.proof).name)
        )
    if finding.fingerprint:
        rows.append(
            "<dt>Fingerprint</dt><dd>%s</dd>" % _esc(finding.fingerprint)
        )
    if finding.proof_error:
        rows.append("<dt>Reason</dt><dd>%s</dd>" % _esc(finding.proof_error))
    return "<dl class=\"proof\">%s</dl>" % "".join(rows)


def _finding_html(finding: Finding) -> str:
    request = finding.request
    method = request.get("method") or "GET"
    url = request.get("url") or ""
    parts = [
        "<article class=\"finding\">",
        "<h2>%s <span class=\"verdict\">%s</span></h2>"
        % (_esc(finding.probe), _esc(finding.verdict)),
    ]
    if finding.cause:
        parts.append("<p><strong>Cause:</strong> %s</p>" % _esc(finding.cause))
    parts.append("<h3>Evidence</h3><pre>%s</pre>" % _esc(finding.evidence))
    parts.append(
        "<h3>Request</h3><p><code>%s</code> %s</p><pre>%s</pre>"
        % (
            _esc(method),
            _esc(url),
            _esc(_headers_text(request.get("headers"))),
        )
    )
    response = finding.response
    if response is None:
        parts.append("<h3>Response</h3><p>No response captured.</p>")
    else:
        parts.append(
            "<h3>Response</h3><p>Status: %s</p><pre>%s</pre><pre>%s</pre>"
            % (
                _esc(response.get("status")),
                _esc(_headers_text(response.get("headers"))),
                _esc(response.get("body")),
            )
        )
    parts.append("<h3>Proof</h3>%s" % _proof_html(finding))
    parts.append("</article>")
    return "\n".join(parts)


def _observation_html(observation) -> str:
    if not isinstance(observation, dict):
        return ""
    request = observation.get("request") or {}
    response = observation.get("response")
    parts = [
        "<article class=\"finding\">",
        "<h2>%s <span class=\"verdict\">%s</span></h2>"
        % (
            _esc(observation.get("probe", "observation")),
            _esc(observation.get("status", "")),
        ),
        "<p><strong>Hardening observation, not a verdict.</strong> It is not "
        "signed and does not count as EXPOSED.</p>",
        "<h3>Evidence</h3><pre>%s</pre>"
        % _esc(observation.get("evidence", "")),
    ]
    missing = observation.get("missing")
    if isinstance(missing, list):
        parts.append(
            "<p><strong>Missing:</strong> %s</p>"
            % _esc(", ".join(str(item) for item in missing) or "none")
        )
    present = observation.get("present")
    if isinstance(present, list):
        parts.append(
            "<p><strong>Present:</strong> %s</p>"
            % _esc(", ".join(str(item) for item in present) or "none")
        )
    parts.append(
        "<h3>Request</h3><p><code>%s</code> %s</p><pre>%s</pre>"
        % (
            _esc(request.get("method", "GET")),
            _esc(request.get("url", "")),
            _esc(_headers_text(request.get("headers"))),
        )
    )
    if response is None:
        parts.append("<h3>Response</h3><p>No response captured.</p>")
    else:
        parts.append(
            "<h3>Response</h3><p>Status: %s</p><pre>%s</pre><pre>%s</pre>"
            % (
                _esc(response.get("status")),
                _esc(_headers_text(response.get("headers"))),
                _esc(response.get("body")),
            )
        )
    parts.append("</article>")
    return "\n".join(parts)


def _target_html(report: Report) -> str:
    target = report.target
    rows = [
        ("Target", _target_basename(target.get("path", ""))),
        ("Kind", target.get("kind")),
    ]
    if target.get("kind") == "live":
        rows.append(("URL", target.get("url") or target.get("path")))
        rows.append(("Ownership proof", target.get("ownership_proof")))
    else:
        dirty = target.get("git_dirty")
        dirty_text = "unknown" if dirty is None else ("yes" if dirty else "no")
        rows.append(("Commit", target.get("git_commit")))
        rows.append(("Dirty", dirty_text))
    rows.extend(
        [
            ("Snapshot", report.snapshot_id),
            ("Run created", report.snapshot.get("created_at")),
            ("Results created", report.created_at),
        ]
    )
    return "<dl class=\"meta\">%s</dl>" % "".join(
        "<dt>%s</dt><dd>%s</dd>" % (_esc(name), _esc(value))
        for name, value in rows
    )


def _counts_html(report: Report) -> str:
    cells = "".join(
        "<tr><th>%s</th><td>%s</td></tr>"
        % (_esc(verdict), _esc(report.counts.get(verdict, 0)))
        for verdict in VERDICTS
    )
    return "<table class=\"counts\">%s</table>" % cells


def render_html(report: Report) -> str:
    """Render one self-contained HTML page; every dynamic value is escaped."""
    basename = _target_basename(report.target.get("path", ""))
    findings = "\n".join(_finding_html(finding) for finding in report.findings)
    if not findings:
        findings = "<p>No probe results were recorded for this run.</p>"
    return """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Pry Findings Report - {title}</title>
<style>
body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
  margin: 2rem auto; max-width: 60rem; padding: 0 1rem; color: #1b1b1b;
  background: #fafafa; line-height: 1.5; }}
h1, h2, h3 {{ line-height: 1.2; }}
h1 {{ margin-bottom: 0.25rem; }}
.lede {{ color: #555; margin-top: 0; }}
.disclaimer {{ border-left: 4px solid #b45309; background: #fff7ed;
  padding: 0.75rem 1rem; margin: 1.5rem 0; }}
.meta, .proof {{ display: grid; grid-template-columns: 12rem 1fr;
  gap: 0.25rem 1rem; }}
.meta dt, .proof dt {{ font-weight: 600; }}
.meta dd, .proof dd {{ margin: 0; overflow-wrap: anywhere; }}
.counts {{ border-collapse: collapse; margin: 1rem 0; }}
.counts th, .counts td {{ border: 1px solid #d4d4d4; padding: 0.25rem 1rem;
  text-align: left; }}
.finding {{ background: #fff; border: 1px solid #d4d4d4; border-radius: 6px;
  padding: 0.75rem 1rem; margin: 1.5rem 0; }}
.verdict {{ font-size: 0.8em; border: 1px solid #999; border-radius: 4px;
  padding: 0 0.35rem; vertical-align: middle; }}
pre {{ background: #f4f4f4; padding: 0.5rem; overflow-x: auto;
  white-space: pre-wrap; overflow-wrap: anywhere; }}
code {{ background: #f4f4f4; padding: 0 0.2rem; }}
footer {{ color: #666; border-top: 1px solid #d4d4d4; margin-top: 2rem;
  padding-top: 0.75rem; font-size: 0.9em; }}
</style>
</head>
<body>
<header>
<h1>Pry Findings Report</h1>
<p class="lede">A local, read-only view over one scan run. The signed proof
bundles are the evidence; this HTML file is not signed.</p>
</header>
<section class="disclaimer">
<h2>What this report does not claim</h2>
<p><strong>No secure verdict.</strong> Pry does not certify this app as secure. NOT_REPRODUCED means a suspected issue could not be confirmed; it is not proof of absence. Absence of a reproduced finding is not a guarantee of safety.</p>
<p><strong>What VALID means.</strong> VALID means the bundle's embedded key verified the signature. It is tamper-evidence, not proof of who created it; pin the fingerprint to trust a signer.</p>
<p><strong>Deferred checks.</strong> Endpoint discovery, IDOR discovery, provider database/open-rule checks, general authenticated scanning, write-based checks, live SSRF, live rate-limit probing, and Level 2 are not implemented. Configured live and local IDOR checks, exposed database files, local Level 1 SSRF, a bounded local rate-limit observation, and opt-in header observations are available.</p>
</section>
<section>
<h2>Target</h2>
{target}
</section>
<section>
<h2>Counts</h2>
{counts}
</section>
<section>
<h2>Observations</h2>
<p class="lede">Hardening observations are not verdicts and are not signed.</p>
{observations}
</section>
<section>
<h2>Findings</h2>
{findings}
</section>
<footer>Local report, no upload. The proof bundles, not this page, are the
signed evidence.</footer>
</body>
</html>
""".format(
        title=_esc(basename),
        target=_target_html(report),
        counts=_counts_html(report),
        observations="\n".join(
            _observation_html(entry) for entry in report.observations
        )
        or "<p>No hardening observations were recorded.</p>",
        findings=findings,
    )


def write_report(run_dir, out=None) -> Path:
    """Atomically write 0600 HTML, defaulting to ``run_dir/report.html``."""
    report = load_run(run_dir)
    target = Path(out) if out is not None else Path(run_dir) / REPORT_FILE
    directory = target.parent
    temp = directory / (target.name + ".tmp")
    try:
        directory.mkdir(parents=True, exist_ok=True)
        temp.write_text(render_html(report), encoding="utf-8")
        os.chmod(str(temp), 0o600)
        os.replace(str(temp), str(target))
    except OSError as exc:
        try:
            temp.unlink()
        except OSError:
            pass
        raise ReportError(
            REPORT_FAILED, "cannot write report: %s" % exc
        ) from exc
    return target
