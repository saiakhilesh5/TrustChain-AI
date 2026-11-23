"""Install script analysis: package.json lifecycle scripts executing remote code."""

import json
import re
from pathlib import Path

LIFECYCLE_SCRIPTS = ("preinstall", "install", "postinstall", "preprepare", "prepare", "postprepare")

RISKY_PATTERNS = [
    (re.compile(r"curl[^|;&]*\|"), "curl-piped-to-shell"),
    (re.compile(r"wget[^|;&]*\|"), "wget-piped-to-shell"),
    (re.compile(r"eval\s*[(\s]"), "eval-usage"),
    (re.compile(r"\bnode\s+-e\s+"), "inline-node-eval"),
    (re.compile(r"Base64|atob|Buffer\.from\(['\"][A-Za-z0-9+/=]{40,}"), "possible-obfuscated-payload"),
    (re.compile(r"(curl|wget)\s+[^|;&]*(http|https)://(?!registry\.(npmjs|yarnpkg)\.org)"), "download-from-non-registry-host"),
]


def scan_install_scripts(repo_root: str) -> list[dict]:
    root = Path(repo_root)
    findings = []
    for package_json in root.rglob("package.json"):
        parts = set(package_json.relative_to(root).parts)
        if parts & {"node_modules", ".git", ".yarn"}:
            continue
        rel = str(package_json.relative_to(root))
        try:
            data = json.loads(package_json.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            continue
        scripts = data.get("scripts") or {}
        name = data.get("name", package_json.parent.name)
        for script_name, script_body in scripts.items():
            if script_name not in LIFECYCLE_SCRIPTS:
                continue
            for pattern, label in RISKY_PATTERNS:
                if pattern.search(script_body):
                    findings.append({
                        "type": "anomaly",
                        "anomaly": f"unsafe-install-script:{label}",
                        "component": name,
                        "detail": f"Lifecycle script '{script_name}' in package '{name}' matches '{label}' — install scripts run automatically with user privileges.",
                        "severity": "HIGH",
                        "verified": True,
                        "evidence": {
                            "kind": "install-script",
                            "path": rel,
                            "script": script_name,
                            "content": script_body[:300],
                        },
                    })
    return findings
