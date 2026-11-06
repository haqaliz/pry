"""Command line interface for Pry."""

import argparse
from typing import List, Optional


def build_parser() -> argparse.ArgumentParser:
    return argparse.ArgumentParser(
        prog="pry",
        description="Pry - Proves an app you own is exposed by actually trying the exploit",
    )


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    parser.parse_args(argv)
    parser.print_help()
    return 1
