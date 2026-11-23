"""TrustChain-AI command line interface."""

import argparse
import sys

from trustchain import __version__


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

    print(f"trustchain {__version__} — command '{args.command}' is not implemented yet", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
