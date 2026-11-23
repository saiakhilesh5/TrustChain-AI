"""TrustChain-AI command line interface."""

import argparse
import json
import sys
from pathlib import Path

from trustchain import __version__
from trustchain.discovery import discover
from trustchain.graph import build_graph, generate_cyclonedx, render_html


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
    scan.add_argument("--no-vulns", action="store_true", help="Skip OSV vulnerability correlation")

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
    inventory_dict = inventory.to_dict()

    out_file = output / "inventory.json"
    out_file.write_text(json.dumps(inventory_dict, indent=2), encoding="utf-8")

    sbom = generate_cyclonedx(inventory_dict)
    (output / "sbom.cdx.json").write_text(json.dumps(sbom, indent=2), encoding="utf-8")

    stats = inventory_dict["stats"]
    print(f"[discover] {stats['total']} components ({stats['direct']} direct, {stats['transitive']} transitive)")
    print(f"[sbom]     CycloneDX written to {output / 'sbom.cdx.json'}")
    print(f"[discover] inventory written to {out_file}")

    if not args.no_vulns:
        from trustchain.scan.correlate import scan_vulnerabilities

        print(f"[osv]      correlating {stats['total']} components with OSV.dev (cached) ...")
        findings = scan_vulnerabilities(inventory_dict, cache_dir=output)
        (output / "vulnerabilities.json").write_text(
            json.dumps(findings, indent=2), encoding="utf-8"
        )
        by_severity: dict[str, int] = {}
        for finding in findings:
            by_severity[finding["severity"]] = by_severity.get(finding["severity"], 0) + 1
        print(f"[osv]      {len(findings)} findings: " + ", ".join(
            f"{count} {sev.lower()}" for sev, count in sorted(by_severity.items(), reverse=True)
        ))

    from trustchain.anomaly import scan_anomalies

    print(f"[anomaly]  scanning CI workflows, Dockerfiles, install scripts, typosquats ...")
    anomalies = scan_anomalies(args.target, inventory_dict)
    (output / "anomalies.json").write_text(json.dumps(anomalies, indent=2), encoding="utf-8")
    by_anomaly: dict[str, int] = {}
    for finding in anomalies:
        by_anomaly[finding["anomaly"]] = by_anomaly.get(finding["anomaly"], 0) + 1
    print(f"[anomaly]  {len(anomalies)} findings: " + (
        ", ".join(f"{count} {label}" for label, count in sorted(by_anomaly.items()))
        or "none"
    ))
    return 0


def _cmd_graph(args) -> int:
    inventory_file = Path(args.output) / "inventory.json"
    if not inventory_file.exists():
        print(f"no inventory found at {inventory_file} — run 'scan' first", file=sys.stderr)
        return 1
    inventory = json.loads(inventory_file.read_text(encoding="utf-8"))
    graph = build_graph(inventory)
    highlight = set()
    vuln_file = Path(args.output) / "vulnerabilities.json"
    if vuln_file.exists():
        for finding in json.loads(vuln_file.read_text(encoding="utf-8")):
            highlight.add(finding["component"])
    output = Path(args.output)
    html = render_html(graph, output / "graph.html", highlight=highlight)
    print(f"[graph]    {graph.number_of_nodes()} nodes, {graph.number_of_edges()} edges")
    print(f"[graph]    interactive graph written to {html}")
    return 0


def _cmd_report(args) -> int:
    print(f"report command is not implemented yet", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
