"""Day 1 checklist: maps the hackathon's Day 1 requirements onto scan artifacts."""

import json
from pathlib import Path


def build_checklist(run_dir: str | Path, steps: list[dict] | None = None) -> dict:
    run_dir = Path(run_dir)
    step_status = {s["id"]: s["status"] for s in (steps or [])}
    step_detail = {s["id"]: s.get("detail", "") for s in (steps or [])}

    inventory = _load(run_dir / "inventory.json") or {}
    stats = inventory.get("stats", {})
    vulnerabilities = _load(run_dir / "vulnerabilities.json") or []
    anomalies = _load(run_dir / "anomalies.json") or []
    graph = _load(run_dir / "graph.json") or {}
    sbom_exists = (run_dir / "sbom.cdx.json").exists()
    evidence = _load(run_dir / "evidence.json") or {}
    evidence_stats = evidence.get("stats", {})

    traced = sum(1 for f in vulnerabilities if f.get("dependency_paths"))
    by_severity: dict[str, int] = {}
    for finding in vulnerabilities:
        by_severity[finding.get("severity", "?")] = by_severity.get(finding.get("severity", "?"), 0) + 1
    by_anomaly: dict[str, int] = {}
    for finding in anomalies:
        by_anomaly[finding.get("anomaly", "?")] = by_anomaly.get(finding.get("anomaly", "?"), 0) + 1

    vuln_file = run_dir / "vulnerabilities.json"
    items = [
        {
            "id": "discover",
            "title": "Discover components — manifests, lockfiles, direct + transitive deps",
            "detail": (f"{stats.get('total', 0)} components "
                       f"({stats.get('direct', 0)} direct, {stats.get('transitive', 0)} transitive)"
                       if stats else step_detail.get("discover", "not run yet")),
            "status": "done" if stats else _pending_or(step_status, "discover"),
            "evidence": "inventory.json",
        },
        {
            "id": "sbom",
            "title": "Generate SBOM (CycloneDX 1.5) with purls and component origins",
            "detail": f"sbom.cdx.json ({len(inventory.get('components', []))} components)" if sbom_exists
                      else "not generated yet",
            "status": "done" if sbom_exists else _pending_or(step_status, "sbom"),
            "evidence": "sbom.cdx.json",
        },
        {
            "id": "graph",
            "title": "Build the dependency graph (root → direct → transitive)",
            "detail": (f"{graph.get('stats', {}).get('total_nodes', 0)} nodes, "
                       f"{graph.get('stats', {}).get('total_edges', 0)} edges"
                       if graph else "not built yet"),
            "status": "done" if graph else _pending_or(step_status, "graph"),
            "evidence": "graph.json / graph.html",
        },
        {
            "id": "cicd",
            "title": "Inspect CI/CD workflows and container images",
            "detail": "GitHub Actions workflows, Dockerfiles and install scripts scanned"
                      if (run_dir / "anomalies.json").exists() else "not scanned yet",
            "status": "done" if (run_dir / "anomalies.json").exists() else _pending_or(step_status, "anomalies"),
            "evidence": "anomalies.json",
        },
        {
            "id": "vulns",
            "title": "Detect vulnerabilities — CVE, severity, fixes, traced to source",
            "detail": (f"{len(vulnerabilities)} findings, {traced} with dependency paths: " + ", ".join(
                f"{count} {sev.lower()}" for sev, count in sorted(by_severity.items(), reverse=True)
            ) if vuln_file.exists() else "not correlated yet"),
            "status": "done" if vuln_file.exists() else _pending_or(step_status, "vulns"),
            "evidence": "vulnerabilities.json",
        },
        {
            "id": "anomalies",
            "title": "Detect suspicious changes — typosquats, CI pinning, scripts, images",
            "detail": (f"{len(anomalies)} anomalies: " + (
                ", ".join(f"{count} {label}" for label, count in sorted(by_anomaly.items())) or "none"
            ) if (run_dir / "anomalies.json").exists() else "not scanned yet"),
            "status": "done" if (run_dir / "anomalies.json").exists() else _pending_or(step_status, "anomalies"),
            "evidence": "anomalies.json",
        },
        {
            "id": "evidence",
            "title": "Present evidence — component, dependency path, evidence, risk level",
            "detail": (f"{evidence_stats.get('total', 0)} ledger entries "
                       f"({evidence_stats.get('verified', 0)} verified, "
                       f"{evidence_stats.get('inferred', 0)} inferred)")
                       if evidence_stats else "report not generated yet",
            "status": "done" if evidence_stats else _pending_or(step_status, "report"),
            "evidence": "evidence.json / guardian_report.html",
        },
    ]
    done = sum(1 for item in items if item["status"] == "done")
    return {
        "items": items,
        "completed": done,
        "total": len(items),
        "percent": round(100 * done / len(items)),
    }


def _pending_or(step_status: dict, step_id: str) -> str:
    status = step_status.get(step_id)
    if status == "running":
        return "running"
    if status == "error":
        return "error"
    return "pending"


def _load(path: Path):
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))
