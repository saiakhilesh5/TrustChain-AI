"""Correlate inventory components with OSV advisories into vulnerability findings."""

from datetime import datetime, timezone

from trustchain.graph import trace_to_roots
from trustchain.graph.depgraph import build_graph
from trustchain.scan.osv import OsvClient

_SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MODERATE": 2, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0}


def scan_vulnerabilities(inventory: dict, cache_dir=None) -> list[dict]:
    """Returns findings: one per (component, advisory) with evidence and paths."""
    components = inventory["components"]
    component_by_key = {c["key"]: c for c in components}

    client = OsvClient(cache_dir=cache_dir)
    vuln_ids_by_key = client.query_batch(components)

    unique_ids = sorted({vid for ids in vuln_ids_by_key.values() for vid in ids})
    advisories = {}
    for vuln_id in unique_ids:
        advisories[vuln_id] = client.get_vuln(vuln_id)

    graph = build_graph(inventory)

    findings = []
    for component_key, vuln_ids in vuln_ids_by_key.items():
        if not vuln_ids:
            continue
        component = component_by_key[component_key]
        paths = trace_to_roots(graph, component_key, limit=5)
        for vuln_id in vuln_ids:
            advisory = advisories[vuln_id]
            findings.append(_build_finding(component, advisory, paths))

    findings.sort(key=lambda f: (-_SEVERITY_ORDER.get(f["severity"], 0), f["component"]))
    return findings


def _build_finding(component: dict, advisory: dict, paths: list[list[str]]) -> dict:
    fixed_versions = _fixed_versions(advisory, component)
    severity = _severity(advisory)
    aliases = [a for a in advisory.get("aliases", []) if a.startswith("CVE-")]
    return {
        "type": "vulnerability",
        "component": component["key"],
        "component_name": component["name"],
        "version": component["version"],
        "ecosystem": component["ecosystem"],
        "scope": component["scope"],
        "advisory_id": advisory["id"],
        "cve": aliases[0] if aliases else advisory["id"],
        "aliases": aliases,
        "summary": advisory.get("summary", ""),
        "severity": severity,
        "fixed_versions": sorted(set(fixed_versions)),
        "dependency_paths": [[component_by_key_label(p) for p in path] for path in paths],
        "references": [r.get("url") for r in advisory.get("references", []) if r.get("url")][:5],
        "evidence": {
            "source": "OSV.dev",
            "advisory_url": f"https://osv.dev/vulnerability/{advisory['id']}",
            "advisory_modified": advisory.get("modified", ""),
            "detected_at": datetime.now(timezone.utc).isoformat(),
        },
        "verified": True,  # advisory match is tool-derived, not AI inference
    }


def component_by_key_label(key: str) -> str:
    # keys look like "npm:lodash@4.17.21"
    return key.split(":", 1)[1] if ":" in key else key


def _fixed_versions(advisory: dict, component: dict) -> list[str]:
    fixed = []
    for affected in advisory.get("affected", []):
        pkg = affected.get("package", {})
        if pkg.get("name") == component["name"]:
            for range_ in affected.get("ranges", []):
                for event in range_.get("events", []):
                    if "fixed" in event:
                        fixed.append(event["fixed"])
    return fixed


def _severity(advisory: dict) -> str:
    for score in advisory.get("severity", []):
        if score.get("type") == "CVSS_V3":
            try:
                vector = score["score"]
                return _cvss_severity(_cvss_score_from_vector(vector))
            except Exception:
                continue
    specific = advisory.get("database_specific", {})
    label = str(specific.get("severity", "UNKNOWN")).upper()
    return label if label in _SEVERITY_ORDER else "UNKNOWN"


def _cvss_score_from_vector(vector: str) -> float:
    """CVSS v3.1 base score from a vector string, per the FIRST spec."""
    import math

    metrics = dict(part.split(":", 1) for part in vector.split("/"))
    weights = {
        "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
        "AC": {"L": 0.77, "H": 0.44},
        "PR": {"N": 0.85, "L": 0.62, "H": 0.27},
        "UI": {"N": 0.85, "R": 0.62},
    }
    impact_value = {"H": 0.56, "L": 0.22, "N": 0.0}
    scope_changed = metrics.get("S") == "C"
    c = impact_value.get(metrics.get("C", "N"), 0.0)
    i = impact_value.get(metrics.get("I", "N"), 0.0)
    a = impact_value.get(metrics.get("A", "N"), 0.0)

    exploitability = 8.22 * (
        weights["AV"][metrics.get("AV", "N")]
        * weights["AC"][metrics.get("AC", "L")]
        * weights["PR"][metrics.get("PR", "N")]
        * weights["UI"][metrics.get("UI", "N")]
    )
    iss = 1 - (1 - c) * (1 - i) * (1 - a)
    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss
    if iss <= 0:
        return 0.0
    if scope_changed:
        score = min(1.08 * (impact + exploitability), 10)
    else:
        score = min(impact + exploitability, 10)
    return min(math.ceil(score * 10) / 10, 10)


def _cvss_severity(score: float) -> str:
    if score <= 0:
        return "UNKNOWN"
    if score < 4:
        return "LOW"
    if score < 7:
        return "MEDIUM"
    if score < 9:
        return "HIGH"
    return "CRITICAL"
