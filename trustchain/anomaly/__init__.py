from trustchain.anomaly.ci import scan_workflows
from trustchain.anomaly.diff import diff_inventories
from trustchain.anomaly.docker import scan_dockerfiles
from trustchain.anomaly.scripts import scan_install_scripts
from trustchain.anomaly.typosquat import scan_typosquats

__all__ = [
    "scan_workflows",
    "scan_dockerfiles",
    "scan_install_scripts",
    "scan_typosquats",
    "diff_inventories",
]


def scan_anomalies(repo_root: str, inventory: dict) -> list[dict]:
    """Run all deterministic anomaly detectors against a repository snapshot."""
    findings = []
    findings.extend(scan_workflows(repo_root))
    findings.extend(scan_dockerfiles(repo_root))
    findings.extend(scan_install_scripts(repo_root))
    findings.extend(scan_typosquats(inventory))
    return findings
