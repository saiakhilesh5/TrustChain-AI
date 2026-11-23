"""Retrospective validation harness.

Ground truth: dependabot "bump X from A to B" commits in the target repo's
history. For each, OSV confirms whether A was vulnerable and B is fixed.
The Guardian is then run on the pre-fix snapshot (git worktree at the parent
commit) and scored on whether it detects the known vulnerability.

Scored capabilities:
- version-change detection (diff anomaly detector)
- vulnerability detection on the pre-fix snapshot (OSV correlation)
"""

import json
import re
import shutil
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from trustchain.anomaly.diff import diff_inventories
from trustchain.discovery import discover
from trustchain.scan.correlate import scan_vulnerabilities
from trustchain.scan.osv import OsvClient

BUMP_RE = re.compile(r"^chore\(deps\w*\): bump (?P<name>\S+) from (?P<from>\S+) to (?P<to>\S+)")


def find_bump_commits(repo: Path, limit: int = 12) -> list[dict]:
    log = _git(repo, "log", "--oneline", "-i", "--grep=^chore\\(deps.*\\): bump .* from .* to .*", "-E", f"-n{limit * 3}")
    commits = []
    for line in log.splitlines():
        sha, subject = line.split(" ", 1)
        match = BUMP_RE.match(subject)
        if match:
            commits.append({
                "sha": sha,
                "subject": subject,
                "name": match["name"],
                "from_version": match["from"],
                "to_version": match["to"].rstrip("()"),
            })
        if len(commits) >= limit:
            break
    return commits


def run_validation(repo: str, limit: int = 12, cache_dir: Path | None = None) -> dict:
    repo_path = Path(repo).resolve()
    cache_dir = cache_dir or (repo_path.parent.parent / "outputs" / "osv_validation_cache")
    commits = find_bump_commits(repo_path, limit=limit)
    client = OsvClient(cache_dir=cache_dir)

    cases = []
    tmp = Path(tempfile.mkdtemp(prefix="trustchain_validation_"))
    worktree = tmp / "snapshot"
    try:
        _git(repo_path, "worktree", "add", "--detach", str(worktree), "HEAD")
        for commit in commits:
            case = _validate_case(repo_path, worktree, commit, client)
            cases.append(case)
        _git(repo_path, "worktree", "remove", "--force", str(worktree), check=False)
    finally:
        # git object files are read-only; cleanup is best-effort on Windows
        shutil.rmtree(tmp, ignore_errors=True)

    detected = [c for c in cases if c["is_security_fix"] and c["vulnerability_detected"]]
    ground_truth = [c for c in cases if c["is_security_fix"]]
    diff_detected = [c for c in cases if c["version_change_detected"]]
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "repository": str(repo_path),
        "commits_analyzed": len(cases),
        "ground_truth_security_fixes": len(ground_truth),
        "vulnerability_detection": {
            "ground_truth": len(ground_truth),
            "detected": len(detected),
            "missed": len(ground_truth) - len(detected),
            "recall": round(len(detected) / len(ground_truth), 3) if ground_truth else None,
        },
        "version_change_detection": {
            "detected": len(diff_detected),
            "total": len(cases),
            "recall": round(len(diff_detected) / len(cases), 3) if cases else None,
        },
        "cases": cases,
    }


def _validate_case(repo: Path, worktree: Path, commit: dict, client: OsvClient) -> dict:
    name, from_v, to_v = commit["name"], commit["from_version"], commit["to_version"]
    from_ids = set(client.query_vuln_ids("npm", name, from_v))
    to_ids = set(client.query_vuln_ids("npm", name, to_v))
    fixed_ids = from_ids - to_ids
    is_security_fix = len(fixed_ids) > 0

    parent = _git(repo, "rev-parse", f"{commit['sha']}^").strip()

    _git_worktree_checkout(worktree, parent)
    inv_pre = discover(str(worktree)).to_dict()
    findings = scan_vulnerabilities(inv_pre, cache_dir=client.cache_dir)
    expected_key = f"npm:{name}@{from_v}"
    detected_ids = {
        f.get("advisory_id") for f in findings if f["component"] == expected_key
    } | {
        f.get("cve") for f in findings if f["component"] == expected_key
    }
    vulnerability_detected = bool(detected_ids & from_ids) if from_ids else None

    _git_worktree_checkout(worktree, commit["sha"])
    inv_post = discover(str(worktree)).to_dict()
    diffs = diff_inventories(inv_pre, inv_post)
    version_change_detected = any(
        d["anomaly"] == "dependency-version-changed"
        and d.get("component_name") == name
        and d.get("evidence", {}).get("previous_version") == from_v
        and d.get("version") == to_v
        for d in diffs
    )

    return {
        "commit": commit["sha"],
        "subject": commit["subject"],
        "package": name,
        "from_version": from_v,
        "to_version": to_v,
        "is_security_fix": is_security_fix,
        "advisories_fixed": sorted(fixed_ids),
        "advisories_pre": sorted(from_ids),
        "vulnerability_detected": vulnerability_detected,
        "detected_advisories": sorted(detected_ids & from_ids),
        "version_change_detected": version_change_detected,
    }


def _git_worktree_checkout(worktree: Path, sha: str) -> None:
    _git(worktree, "checkout", "--detach", sha)


def _git(repo: Path, *args: str, check: bool = True) -> str:
    result = subprocess.run(
        ["git", "-C", str(repo), *args],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
    )
    if check and result.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)} failed: {result.stderr.strip()}")
    return result.stdout
