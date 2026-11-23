"""TrustChain-AI command line interface."""

import argparse
import json
import sys
from pathlib import Path

from trustchain import __version__
from trustchain.discovery import discover


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="trustchain",
        description="TrustChain-AI: Software Supply Chain Guardian",
    )
    parser.add_argument("--version", action="version", version=f"trustchain {__version__}")

    subparsers = parser.add_subparsers(dest="command")

    scan = subparsers.add_parser("scan", help="Run the discovery + detection pipeline")
    scan.add_argument("--target", required=True, help="Path to the repository to scan")
    scan.add_argument("--output", required=True, help="Directory for scan results")

    graph = subparsers.add_parser("graph", help="Build the dependency graph visualization")
    graph.add_argument("--target", required=True, help="Path to the scanned repository")
    graph.add_argument("--output", required=True, help="Directory for graph output")

    report = subparsers.add_parser("report", help="Generate the Guardian report")
    report.add_argument("--run", required=True, help="Scan output directory")

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command is None:
        parser.print_help()
        return 1

    if args.command == "scan":
        return _cmd_scan(args)
    if args.command == "graph":
        return _cmd_graph(args)
    if args.command == "report":
        return _cmd_report(args)

    return 0


def _cmd_scan(args) -> int:
    print(f"[discover] scanning {args.target} ...")
    inventory = discover(args.target)
    output = Path(args.output)
    output.mkdir(parents=True, exist_ok=True)
    out_file = output / "inventory.json"
    out_file.write_text(json.dumps(inventory.to_dict(), indent=2), encoding="utf-8")
    stats = inventory.to_dict()["stats"]
    print(f"[discover] {stats['total']} components ({stats['direct']} direct, {stats['transitive']} transitive)")
    print(f"[discover] inventory written to {out_file}")
    return 0


def _cmd_graph(args) -> int:
    print(f"graph command is not implemented yet", file=sys.stderr)
    return 2


def _cmd_report(args) -> int:
    print(f"report command is not implemented yet", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
