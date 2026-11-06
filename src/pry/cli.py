"""Command line interface for Pry."""

import argparse
import json
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
from pry.own.tokens import OwnershipToken, TokenSigner
from pry.own.verify import METHODS, new_challenge, verify_target

_USAGE_CAUSES = {UNSUPPORTED_TARGET, BAD_CHALLENGE, UNSUPPORTED_METHOD, NO_METHOD}


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
    scan.add_argument("target", help="URL or bare host to scan")
    scan.add_argument("--token", help="Ownership token from verify-ownership")
    scan.add_argument("--token-file", help="Read the ownership token from a file")
    scan.add_argument(
        "--level",
        type=int,
        default=0,
        choices=[0, 1, 2],
        help="Intensity level (only 0 is implemented)",
    )
    scan.add_argument(
        "--confirm",
        action="store_true",
        help="Confirm higher-intensity actions (not usable yet)",
    )

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


def cmd_scan(args) -> int:
    try:
        target = normalize_target(args.target)
        token = _resolve_token(args)
        proof = TokenSigner().validate(token, target)
    except OwnershipError as exc:
        _print_error(exc)
        return 2

    if args.level != 0:
        _print_error(
            OwnershipError(
                INTENSITY_INSUFFICIENT, "only level 0 is implemented"
            )
        )
        return 2

    return run_scan(proof)


def run_scan(proof: OwnershipToken) -> int:
    print("UNVERIFIED: PROBE_INCONCLUSIVE: probe suite not implemented")
    return 1


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
    if args.command == "intake":
        return cmd_intake(args)
    return cmd_scan(args)


if __name__ == "__main__":
    raise SystemExit(main())
