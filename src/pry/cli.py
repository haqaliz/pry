"""Command line interface for Pry."""

import argparse
import json
import sys
from dataclasses import asdict
from pathlib import Path
from typing import List, Optional

from pry.intake import intake
from pry.intake.errors import IntakeError
from pry.own.errors import (
    BAD_CHALLENGE,
    INTENSITY_INSUFFICIENT,
    NO_METHOD,
    TOKEN_MALFORMED,
    UNSUPPORTED_METHOD,
    UNSUPPORTED_TARGET,
    OwnershipError,
)
from pry.own.target import Target, normalize_target
from pry.own.tokens import TokenSigner
from pry.own.verify import METHODS, new_challenge, verify_target
from pry.probe import EXPOSED, ProbeError, ProbeResult, summarize
from pry.probe.idor import load_idor_config
from pry.probe.live import scan_live
from pry.probe.rate_limit import (
    LIVE_RATE_LIMIT_DEFAULT_COUNT,
    LIVE_RATE_LIMIT_MAX_COUNT,
    RATE_LIMIT_DEFAULT_COUNT,
    validate_rate_limit,
)
from pry.probe.scan import scan_local, validate_endpoints
from pry.probe.ssrf import validate_ssrf
from pry.probe.write import load_write_config
from pry.proof import ProofError, load_bundle, verify_bundle
from pry.report import ReportError, load_run, write_report

_USAGE_CAUSES = {UNSUPPORTED_TARGET, BAD_CHALLENGE, UNSUPPORTED_METHOD, NO_METHOD}

CONFIRMATION_REQUIRED = "CONFIRMATION_REQUIRED"
SSRF_CONFIG_REQUIRED = "SSRF_CONFIG_REQUIRED"
SSRF_REQUIRES_LEVEL1 = "SSRF_REQUIRES_LEVEL1"
SSRF_REQUIRES_LOCAL = "SSRF_REQUIRES_LOCAL"
RATE_LIMIT_CONFIG_REQUIRED = "RATE_LIMIT_CONFIG_REQUIRED"
RATE_LIMIT_REQUIRES_LEVEL1 = "RATE_LIMIT_REQUIRES_LEVEL1"
LEVEL1_CHECK_REQUIRED = "LEVEL1_CHECK_REQUIRED"
LEVEL1_REQUIRES_LOCAL = "LEVEL1_REQUIRES_LOCAL"
WRITE_CONFIG_REQUIRED = "WRITE_CONFIG_REQUIRED"
WRITE_REQUIRES_LEVEL2 = "WRITE_REQUIRES_LEVEL2"
WRITE_REQUIRES_LOCAL = "WRITE_REQUIRES_LOCAL"
LIVE_WRITE_CONFIRMATION_REQUIRED = "LIVE_WRITE_CONFIRMATION_REQUIRED"
LIVE_WRITE_CONFIRMATION_UNEXPECTED = "LIVE_WRITE_CONFIRMATION_UNEXPECTED"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pry",
        description="Pry - Proves an app you own is exposed by actually trying the exploit",
    )
    subparsers = parser.add_subparsers(dest="command")

    verify = subparsers.add_parser(
        "verify-ownership", help="Prove control of a target before scanning it"
    )
    verify.add_argument("target", help="URL or bare host to verify")
    verify.add_argument(
        "--method",
        required=True,
        choices=sorted(METHODS),
        help="Verification method",
    )
    verify.add_argument(
        "--challenge",
        help="Challenge returned by a previous run; publish it, then pass it here",
    )
    verify.add_argument("--json", action="store_true", help="Print JSON")

    scan = subparsers.add_parser("scan", help="Scan a target that has been verified")
    scan.add_argument("target", help="URL, bare host, or local repository path")
    scan.add_argument("--token", help="Ownership token from verify-ownership")
    scan.add_argument("--token-file", help="Read the ownership token from a file")
    scan.add_argument(
        "--level",
        type=int,
        default=0,
        choices=[0, 1, 2],
        help=(
            "Intensity level (0 floor, 1 local SSRF/rate-limit and live "
            "rate-limit; 2 local/live write confirmation)"
        ),
    )
    scan.add_argument(
        "--confirm",
        action="store_true",
        help="Explicit confirmation for level 1 or level 2 expanded checks",
    )
    scan.add_argument(
        "--confirm-live-write",
        action="store_true",
        help="Extra confirmation for a live level 2 write; it can alter "
        "real data",
    )
    scan.add_argument("--json", action="store_true", help="Print JSON")
    scan.add_argument(
        "--out", help="Run directory for a scan (default: ~/.pry/runs/<id>)"
    )
    scan.add_argument(
        "--timeout", type=float, help="Sandbox readiness timeout in seconds"
    )
    scan.add_argument(
        "--port", type=int, help="Port the app listens on inside the sandbox"
    )
    scan.add_argument(
        "--endpoint",
        action="append",
        default=[],
        metavar="PATH",
        help="Declared-protected path to GET without credentials (repeatable)",
    )
    scan.add_argument(
        "--headers",
        action="store_true",
        help=(
            "Record the recommended response headers on / "
            "(hardening observation, not a verdict)"
        ),
    )
    scan.add_argument(
        "--idor-config",
        metavar="FILE",
        help="0600 JSON config with two identities and two object paths",
    )
    scan.add_argument(
        "--write-config",
        metavar="FILE",
        help="0600 JSON config for a declared local level 2 write",
    )
    scan.add_argument(
        "--ssrf-endpoint",
        metavar="PATH",
        help="Declared fetch endpoint for the local level 1 SSRF check",
    )
    scan.add_argument(
        "--ssrf-parameter",
        metavar="NAME",
        help="Query parameter that takes the callback URL",
    )
    scan.add_argument(
        "--rate-limit-endpoint",
        metavar="PATH",
        help="Declared endpoint for the level 1 rate-limit observation",
    )
    scan.add_argument(
        "--rate-limit-count",
        type=int,
        metavar="N",
        help="Requests for the rate-limit observation, 1-20 local, 1-5 live "
        "(default: 10 local, 5 live)",
    )
    scan.add_argument(
        "--report",
        action="store_true",
        help="Write an HTML findings report after a scan",
    )

    report = subparsers.add_parser(
        "report", help="Generate a local HTML report from a run directory"
    )
    report.add_argument("run_dir", help="Run directory from a local scan")
    report.add_argument(
        "--out", help="Report path (default: RUN_DIR/report.html)"
    )
    report.add_argument(
        "--json", action="store_true", help="Print JSON metadata"
    )

    verify_proof = subparsers.add_parser(
        "verify-proof", help="Verify a signed proof bundle"
    )
    verify_proof.add_argument("file", help="Path to a proof bundle JSON file")
    verify_proof.add_argument(
        "--fingerprint",
        help="Expected sha256:... fingerprint to pin",
    )
    verify_proof.add_argument("--json", action="store_true", help="Print JSON")

    intake_parser = subparsers.add_parser(
        "intake", help="Boot a local repository in a Docker sandbox"
    )
    intake_parser.add_argument("path", help="Path to the local repository")
    intake_parser.add_argument("--json", action="store_true", help="Print JSON")
    intake_parser.add_argument(
        "--out", help="Run directory (default: ~/.pry/runs/<id>)"
    )
    intake_parser.add_argument(
        "--keep", action="store_true", help="Keep the container and workspace"
    )
    intake_parser.add_argument(
        "--port", type=int, help="Port the app listens on inside the sandbox"
    )
    intake_parser.add_argument(
        "--timeout", type=float, help="Readiness timeout in seconds"
    )

    return parser


def _print_error(exc: OwnershipError, as_json: bool = False) -> None:
    if as_json:
        print(
            json.dumps(
                {"status": "unverified", "cause": exc.cause, "message": exc.message}
            )
        )
    else:
        print("UNVERIFIED: %s: %s" % (exc.cause, exc.message))


def _instructions(target: Target, method: str, challenge: str) -> str:
    value = "pry-verify=" + challenge
    if method == "dns":
        return (
            "Ownership not verified yet; no token issued.\n"
            "Add this TXT record, then re-run:\n"
            "  name:    %s\n"
            "  value:   %s\n"
            "  command: pry verify-ownership %s --method dns --challenge %s"
            % (target.dns_name, value, target.origin, challenge)
        )
    return (
        "Ownership not verified yet; no token issued.\n"
        "Publish this file, then re-run:\n"
        "  file:    %s\n"
        "  content: %s\n"
        "  command: pry verify-ownership %s --method well-known --challenge %s"
        % (target.well_known_url, value, target.origin, challenge)
    )


def _resolve_token(args) -> str:
    if args.token and args.token_file:
        raise OwnershipError(
            TOKEN_MALFORMED, "use either --token or --token-file, not both"
        )
    if args.token:
        return args.token
    if args.token_file:
        try:
            return Path(args.token_file).read_text(encoding="utf-8").strip()
        except OSError as exc:
            raise OwnershipError(
                TOKEN_MALFORMED, "cannot read token file: %s" % exc
            ) from exc
    raise OwnershipError(TOKEN_MALFORMED, "no ownership token provided")


def cmd_verify(args) -> int:
    try:
        target = normalize_target(args.target)
    except OwnershipError as exc:
        _print_error(exc, args.json)
        return 2

    if not args.challenge:
        challenge = new_challenge()
        instructions = _instructions(target, args.method, challenge)
        if args.json:
            print(
                json.dumps(
                    {
                        "status": "unverified",
                        "cause": "CHALLENGE_ISSUED",
                        "target": target.origin,
                        "method": args.method,
                        "challenge": challenge,
                        "instructions": instructions,
                    }
                )
            )
        else:
            print(instructions)
        return 1

    try:
        token = verify_target(args.target, args.method, args.challenge)
    except OwnershipError as exc:
        _print_error(exc, args.json)
        return 2 if exc.cause in _USAGE_CAUSES else 1

    if args.json:
        print(
            json.dumps(
                {
                    "status": "verified",
                    "target": target.origin,
                    "proof": METHODS[args.method],
                    "token": token,
                }
            )
        )
    else:
        print("Ownership verified for %s (%s)" % (target.origin, METHODS[args.method]))
        print("Token: %s" % token)
    return 0


def cmd_verify_proof(args) -> int:
    try:
        bundle = load_bundle(args.file)
        payload, fingerprint = verify_bundle(
            bundle, expected_fingerprint=args.fingerprint
        )
    except ProofError as exc:
        if args.json:
            print(
                json.dumps(
                    {
                        "status": "invalid",
                        "cause": exc.cause,
                        "message": exc.message,
                    }
                )
            )
        else:
            print("INVALID: %s: %s" % (exc.cause, exc.message))
        return 1

    finding = payload["finding"]
    target = payload["target"]
    if args.json:
        print(
            json.dumps(
                {
                    "status": "valid",
                    "fingerprint": fingerprint,
                    "finding": finding,
                },
                sort_keys=True,
            )
        )
        return 0

    print("VALID")
    print("Fingerprint: %s" % fingerprint)
    print("Probe: %s" % finding.get("probe"))
    print("Verdict: %s" % finding.get("verdict"))
    print("Target: %s (%s)" % (target.get("path"), target.get("kind")))
    return 0


def cmd_report(args) -> int:
    try:
        report = load_run(args.run_dir)
        path = write_report(args.run_dir, out=args.out)
    except ReportError as exc:
        if args.json:
            print(
                json.dumps(
                    {
                        "status": "failed",
                        "cause": exc.cause,
                        "message": exc.message,
                    }
                )
            )
        else:
            print(str(exc))
        return 1

    if args.json:
        print(
            json.dumps(
                {
                    "run_dir": str(Path(args.run_dir).expanduser()),
                    "report": str(path),
                    "snapshot_id": report.snapshot_id,
                    "counts": report.counts,
                    "findings": [
                        {
                            "probe": finding.probe,
                            "verdict": finding.verdict,
                            "proof_status": finding.proof_status,
                            "fingerprint": finding.fingerprint,
                        }
                        for finding in report.findings
                    ],
                },
                sort_keys=True,
                indent=2,
            )
        )
    else:
        print("Report: %s" % path)
    return 0


def _looks_local(value: str) -> bool:
    """A URL always has a scheme; otherwise a directory or path-like string is local."""
    if "://" in value:
        return False
    if Path(value).expanduser().is_dir():
        return True
    return value.startswith((".", "/", "~")) or "/" in value or "\\" in value


def _probe_line(result: ProbeResult) -> str:
    return "%s: %s: %s" % (result.probe, result.verdict, result.evidence)


def _observation_line(observation: dict) -> str:
    return "%s: %s: %s" % (
        observation.get("probe"),
        observation.get("status"),
        observation.get("evidence"),
    )


def _scan_target_path(args) -> int:
    has_ssrf_flags = (
        args.ssrf_endpoint is not None or args.ssrf_parameter is not None
    )
    has_rate_limit_flags = (
        args.rate_limit_endpoint is not None
        or args.rate_limit_count is not None
    )
    has_write = args.write_config is not None
    if args.level < 2 and has_write:
        _print_error(
            ProbeError(
                WRITE_REQUIRES_LEVEL2,
                "write confirmation requires --level 2 and --confirm on a "
                "local path",
            )
        )
        return 2

    ssrf_config = None
    rate_limit_config = None
    if args.level in (1, 2):
        if not args.confirm:
            _print_error(
                ProbeError(
                    CONFIRMATION_REQUIRED,
                    "level %d is expanded work and requires --confirm"
                    % args.level,
                )
            )
            return 2
        if args.level == 2 and not has_write:
            _print_error(
                ProbeError(
                    WRITE_CONFIG_REQUIRED,
                    "level 2 requires --write-config",
                )
            )
            return 2
        if args.rate_limit_count is not None and args.rate_limit_endpoint is None:
            _print_error(
                ProbeError(
                    RATE_LIMIT_CONFIG_REQUIRED,
                    "level %d rate-limit checks require "
                    "--rate-limit-endpoint" % args.level,
                )
            )
            return 2
        if has_ssrf_flags and (
            args.ssrf_endpoint is None or args.ssrf_parameter is None
        ):
            _print_error(
                ProbeError(
                    SSRF_CONFIG_REQUIRED,
                    "level %d requires --ssrf-endpoint and --ssrf-parameter"
                    % args.level,
                )
            )
            return 2
        if (
            args.level == 1
            and not has_ssrf_flags
            and not has_rate_limit_flags
            and not args.idor_config
        ):
            _print_error(
                ProbeError(
                    LEVEL1_CHECK_REQUIRED,
                    "level 1 requires --ssrf-endpoint and --ssrf-parameter, "
                    "--rate-limit-endpoint, or --idor-config",
                )
            )
            return 2
        try:
            if has_ssrf_flags:
                ssrf_config = validate_ssrf(
                    args.ssrf_endpoint, args.ssrf_parameter
                )
            if args.rate_limit_endpoint is not None:
                rate_limit_config = validate_rate_limit(
                    args.rate_limit_endpoint,
                    args.rate_limit_count
                    if args.rate_limit_count is not None
                    else RATE_LIMIT_DEFAULT_COUNT,
                )
        except ProbeError as exc:
            _print_error(exc)
            return 2
    elif has_ssrf_flags:
        _print_error(
            ProbeError(
                SSRF_REQUIRES_LEVEL1,
                "SSRF checks require --level 1 and --confirm on a local path",
            )
        )
        return 2
    elif has_rate_limit_flags:
        _print_error(
            ProbeError(
                RATE_LIMIT_REQUIRES_LEVEL1,
                "rate-limit observations require --level 1 and --confirm on a "
                "local path",
            )
        )
        return 2

    try:
        endpoints = validate_endpoints(args.endpoint)
        idor_config = (
            load_idor_config(args.idor_config) if args.idor_config else None
        )
        write_config = load_write_config(args.write_config) if has_write else None
    except ProbeError as exc:
        _print_error(exc)
        return 2

    kwargs = {
        "out": args.out,
        "timeout": args.timeout,
        "port": args.port,
        "endpoints": endpoints,
    }
    if args.headers:
        kwargs["headers"] = True
    if ssrf_config is not None:
        kwargs["ssrf_config"] = ssrf_config
    if rate_limit_config is not None:
        kwargs["rate_limit_config"] = rate_limit_config
    if idor_config is not None:
        kwargs["idor_config"] = idor_config
    if write_config is not None:
        kwargs["write_config"] = write_config
    try:
        outcome = scan_local(args.target, **kwargs)
    except (IntakeError, ProbeError, ProofError) as exc:
        _print_error(exc)
        return 2

    return _finish_scan(args, outcome)


def _scan_target_url(args) -> int:
    has_write = args.write_config is not None
    has_ssrf_flags = (
        args.ssrf_endpoint is not None or args.ssrf_parameter is not None
    )
    has_rate_limit_flags = (
        args.rate_limit_endpoint is not None
        or args.rate_limit_count is not None
    )

    if args.level == 2 and not has_write:
        _print_error(
            ProbeError(
                WRITE_CONFIG_REQUIRED,
                "level 2 requires --write-config",
            ),
            args.json,
        )
        return 2
    if args.level < 2 and has_write:
        _print_error(
            ProbeError(
                WRITE_REQUIRES_LEVEL2,
                "write confirmation requires --level 2",
            ),
            args.json,
        )
        return 2
    if args.level > 0 and not args.confirm:
        _print_error(
            ProbeError(
                CONFIRMATION_REQUIRED,
                "level %d requires --confirm" % args.level,
            ),
            args.json,
        )
        return 2
    if has_write and not args.confirm_live_write:
        _print_error(
            ProbeError(
                LIVE_WRITE_CONFIRMATION_REQUIRED,
                "live writes can alter real data; add --confirm-live-write "
                "only after reading the warning and preferring a staging copy",
            ),
            args.json,
        )
        return 2
    if args.confirm_live_write and not has_write:
        _print_error(
            ProbeError(
                LIVE_WRITE_CONFIRMATION_UNEXPECTED,
                "--confirm-live-write requires --level 2 --write-config",
            ),
            args.json,
        )
        return 2
    if has_ssrf_flags:
        cause = (
            SSRF_REQUIRES_LOCAL
            if args.level >= 1
            else SSRF_REQUIRES_LEVEL1
        )
        _print_error(
            ProbeError(
                cause,
                "SSRF checks are local-only; live rate-limit is available at "
                "level 1 with --confirm",
            ),
            args.json,
        )
        return 2

    rate_limit_config = None
    if has_rate_limit_flags:
        if args.level < 1:
            _print_error(
                ProbeError(
                    RATE_LIMIT_REQUIRES_LEVEL1,
                    "rate-limit observations require --level 1 and --confirm",
                ),
                args.json,
            )
            return 2
        if args.rate_limit_count is not None and args.rate_limit_endpoint is None:
            _print_error(
                ProbeError(
                    RATE_LIMIT_CONFIG_REQUIRED,
                    "rate-limit checks require --rate-limit-endpoint",
                ),
                args.json,
            )
            return 2
        try:
            rate_limit_config = validate_rate_limit(
                args.rate_limit_endpoint,
                args.rate_limit_count
                if args.rate_limit_count is not None
                else LIVE_RATE_LIMIT_DEFAULT_COUNT,
                max_count=LIVE_RATE_LIMIT_MAX_COUNT,
            )
        except ProbeError as exc:
            _print_error(exc, args.json)
            return 2
    elif args.level == 1:
        _print_error(
            ProbeError(
                LEVEL1_CHECK_REQUIRED,
                "live level 1 requires --rate-limit-endpoint",
            ),
            args.json,
        )
        return 2

    try:
        target = normalize_target(args.target)
        token = _resolve_token(args)
        TokenSigner().validate(token, target)
        endpoints = validate_endpoints(args.endpoint)
        idor_config = (
            load_idor_config(args.idor_config) if args.idor_config else None
        )
        write_config = (
            load_write_config(args.write_config) if has_write else None
        )
    except (OwnershipError, ProbeError) as exc:
        _print_error(exc, args.json)
        return 2

    live_kwargs = {
        "endpoints": endpoints,
        "out": args.out,
        "idor_config": idor_config,
    }
    if args.headers:
        live_kwargs["headers"] = True
    if rate_limit_config is not None:
        live_kwargs["rate_limit_config"] = rate_limit_config
    if write_config is not None:
        live_kwargs["write_config"] = write_config
    try:
        outcome = scan_live(args.target, token, **live_kwargs)
    except (OwnershipError, IntakeError, ProbeError, ProofError) as exc:
        _print_error(exc, args.json)
        return 2

    return _finish_scan(args, outcome)


def _finish_scan(args, outcome) -> int:
    summary = summarize(outcome.results)
    if outcome.corpus_error:
        print(
            "Warning: corpus not written: %s" % outcome.corpus_error,
            file=sys.stderr,
        )

    report_path = None
    if args.report:
        try:
            report_path = write_report(Path(outcome.results_path).parent)
        except ReportError as exc:
            print(str(exc))
            return 2

    if args.json:
        data = {
            "snapshot": outcome.snapshot,
            "results": [asdict(result) for result in outcome.results],
            "observations": outcome.observations,
            "summary": summary,
            "results_path": str(outcome.results_path),
        }
        if report_path is not None:
            data["report"] = str(report_path)
        print(json.dumps(data, sort_keys=True, indent=2))
    else:
        for result in outcome.results:
            print(_probe_line(result))
        for observation in outcome.observations:
            print(_observation_line(observation))
        print("Results: %s" % outcome.results_path)
        if report_path is not None:
            print("Report: %s" % report_path)
    return 1 if summary[EXPOSED] else 0


def cmd_scan(args) -> int:
    if _looks_local(args.target):
        return _scan_target_path(args)
    return _scan_target_url(args)


def cmd_intake(args) -> int:
    try:
        result = intake(
            args.path,
            out=args.out,
            keep=args.keep,
            port=args.port,
            timeout=args.timeout,
        )
    except IntakeError as exc:
        if args.json:
            print(
                json.dumps(
                    {
                        "status": "failed",
                        "cause": exc.cause,
                        "message": exc.message,
                    }
                )
            )
        else:
            print("UNVERIFIED: %s: %s" % (exc.cause, exc.message))
        return 1

    if args.json:
        payload = dict(result.snapshot)
        payload["snapshot_path"] = str(result.snapshot_path)
        print(json.dumps(payload, sort_keys=True, indent=2))
        return 0

    snapshot = result.snapshot
    print("Sandbox ready: %s" % snapshot["sandbox_id"])
    print(
        "Target: %s (%s)"
        % (snapshot["target"]["path"], snapshot["target"]["kind"])
    )
    print("Image: %s" % snapshot["project"]["image"])
    print("Snapshot: %s" % result.snapshot_path)
    if result.kept:
        print("Container: %s (kept)" % result.container_id)
        print("Workspace: %s (kept)" % result.workspace)
        print(
            "Clean up with: docker rm -f %s && rm -rf %s"
            % (result.container_id, result.workspace)
        )
    else:
        print("Container: %s (removed)" % result.container_id)
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command is None:
        parser.print_help()
        return 1
    if args.command == "verify-ownership":
        return cmd_verify(args)
    if args.command == "verify-proof":
        return cmd_verify_proof(args)
    if args.command == "report":
        return cmd_report(args)
    if args.command == "intake":
        return cmd_intake(args)
    return cmd_scan(args)


if __name__ == "__main__":
    raise SystemExit(main())
