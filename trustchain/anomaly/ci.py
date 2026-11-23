"""GitHub Actions workflow analysis: unpinned actions and unsafe run steps."""

import re
from pathlib import Path

import yaml

USES_RE = re.compile(r"^\s*uses:\s*(?P<ref>\S+)")
RUN_RE = re.compile(r"^\s*run:\s*(?P<script>.*)")


def scan_workflows(repo_root: str) -> list[dict]:
    """Find unpinned CI actions and risky run steps under .github/workflows."""
    root = Path(repo_root)
    workflows_dir = root / ".github" / "workflows"
    findings = []
    if not workflows_dir.exists():
        return findings

    for workflow in sorted(workflows_dir.glob("*.y*ml")):
        rel = str(workflow.relative_to(root))
        text = workflow.read_text(encoding="utf-8", errors="replace")
        try:
            data = yaml.safe_load(text)
        except yaml.YAMLError:
            data = None

        findings.extend(_scan_uses(workflow, rel, text))
        findings.extend(_scan_run_steps(workflow, rel, text))
        findings.extend(_scan_trigger_injection(workflow, rel, data))
    return findings


def _scan_uses(workflow: Path, rel: str, text: str) -> list[dict]:
    findings = []
    for line_no, line in enumerate(text.splitlines(), 1):
        match = USES_RE.match(line)
        if not match:
            continue
        ref = match["ref"].strip("\"'")
        if ref.startswith("./") or ref.startswith("docker://"):
            continue
        # pinned by long SHA (40 hex) is safe; tags/branches are mutable
        if not re.search(r"@[0-9a-f]{40}$", ref):
            action = ref.rsplit("@", 1)[0] if "@" in ref else ref
            findings.append({
                "type": "anomaly",
                "anomaly": "unpinned-ci-action",
                "component": action,
                "detail": f"GitHub Action '{ref}' is not pinned to a commit SHA — a mutable tag can be reassigned by the action owner or a compromised account.",
                "severity": "MEDIUM",
                "verified": True,
                "evidence": {
                    "kind": "ci-workflow",
                    "path": rel,
                    "line": line_no,
                    "content": line.strip(),
                },
            })
    return findings


def _scan_run_steps(workflow: Path, rel: str, text: str) -> list[dict]:
    findings = []
    risky_patterns = [
        (re.compile(r"curl[^|;]*\|\s*(sudo\s+)?(ba)?sh"), "curl-piped-to-shell"),
        (re.compile(r"wget[^|;]*\|\s*(sudo\s+)?(ba)?sh"), "wget-piped-to-shell"),
        (re.compile(r"\bdocker\s+(pull|run)\s+\S+:latest"), "docker-latest-tag"),
    ]
    for line_no, line in enumerate(text.splitlines(), 1):
        for pattern, label in risky_patterns:
            if pattern.search(line):
                findings.append({
                    "type": "anomaly",
                    "anomaly": label,
                    "component": rel,
                    "detail": f"Workflow run step contains '{label}': remote content executed without integrity verification.",
                    "severity": "MEDIUM",
                    "verified": True,
                    "evidence": {
                        "kind": "ci-workflow",
                        "path": rel,
                        "line": line_no,
                        "content": line.strip(),
                    },
                })
    return findings


def _scan_trigger_injection(workflow: Path, rel: str, data: dict | None) -> list[dict]:
    """Flag workflows triggered by pull_request_target that check out the PR head —
    a classic privilege-escalation vector."""
    if not isinstance(data, dict):
        return []
    triggers = data.get(True, data.get("on", {}))  # YAML parses 'on' as True
    if "pull_request_target" not in (triggers if isinstance(triggers, dict) else {}):
        return []
    text = workflow.read_text(encoding="utf-8", errors="replace")
    findings = []
    for line_no, line in enumerate(text.splitlines(), 1):
        if "ref:" in line and "refs/pull" in line:
            findings.append({
                "type": "anomaly",
                "anomaly": "pull-request-target-checkout",
                "component": rel,
                "detail": "pull_request_target workflow checks out untrusted PR code with access to repository secrets.",
                "severity": "HIGH",
                "verified": True,
                "evidence": {
                    "kind": "ci-workflow",
                    "path": rel,
                    "line": line_no,
                    "content": line.strip(),
                },
            })
    return findings
