"""Background scan runner: clone a GitHub URL, run the full Day 1 pipeline.

Each run is tracked with step-level progress so the web UI can poll
``/api/runs/<id>`` and show a live checklist. Only public github.com
repositories can be scanned — everything stays inside the local sandbox.
"""

import re
import subprocess
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

from trustchain.anomaly import scan_anomalies
from trustchain.discovery import discover
from trustchain.graph.depgraph import build_graph
from trustchain.graph.sbom import generate_cyclonedx

GITHUB_URL_RE = re.compile(r"^https://github\.com/[A-Za-z0-9_.\-]+/[A-Za-z0-9_.\-]+/?$")

STEPS = [
    ("clone", "Clone / open repository"),
    ("discover", "Discover components (manifests + lockfiles)"),
    ("sbom", "Generate CycloneDX SBOM"),
    ("vulns", "Correlate vulnerabilities (OSV.dev)"),
    ("anomalies", "Detect supply-chain anomalies"),
    ("graph", "Build dependency graph"),
    ("report", "Run Guardian agents + evidence ledger"),
]


class ScanError(Exception):
    pass


class RunManager:
    """Tracks scan runs and executes the pipeline in background threads."""

    def __init__(self, base_dir: str | Path | None = None):
        root = Path(base_dir) if base_dir else Path.cwd()
        self.samples_dir = root / "samples"
        self.outputs_dir = root / "outputs"
        self._runs: dict[str, dict] = {}
        self._lock = threading.Lock()

    @staticmethod
    def normalize_url(url: str) -> str:
        url = url.strip()
        while url.endswith("/"):
            url = url[:-1]
        if url.endswith(".git"):
            url = url[: -len(".git")]
        if not GITHUB_URL_RE.match(url):
            raise ScanError(
                "Only public github.com repository URLs are supported "
                "(https://github.com/<owner>/<repo>)."
            )
        return url

    def start(self, url: str) -> dict:
        url = self.normalize_url(url)
        name = url.rsplit("/", 1)[-1].lower().replace(" ", "-")
        if not re.match(r"^[a-z0-9_.\-]+$", name):
            raise ScanError("invalid repository name derived from URL")

        run_id = f"{name}-{uuid.uuid4().hex[:6]}"
        run = {
            "id": run_id,
            "url": url,
            "name": name,
            "status": "queued",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "steps": [{"id": sid, "label": label, "status": "pending"} for sid, label in STEPS],
            "error": None,
            "run_dir": str(self.outputs_dir / run_id),
        }
        with self._lock:
            self._runs[run_id] = run
        thread = threading.Thread(target=self._execute, args=(run,), daemon=True)
        thread.start()
        return run

    def get(self, run_id: str) -> dict | None:
        with self._lock:
            return self._runs.get(run_id)

    def list_runs(self) -> list[dict]:
        runs = []
        with self._lock:
            runs.extend(self._runs.values())
        known = {r["id"] for r in runs}
        for run_dir in sorted(self.outputs_dir.glob("*/inventory.json"), reverse=True):
            run_id = run_dir.parent.name
            if run_id not in known:
                runs.append({
                    "id": run_id,
                    "url": "",
                    "name": run_id,
                    "status": "done",
                    "created_at": datetime.fromtimestamp(
                        run_dir.stat().st_mtime, tz=timezone.utc
                    ).isoformat(),
                    "steps": [{"id": sid, "label": label, "status": "done"} for sid, label in STEPS],
                    "error": None,
                    "run_dir": str(run_dir.parent),
                })
        return sorted(runs, key=lambda r: r["created_at"], reverse=True)

    # ---- pipeline -------------------------------------------------------

    def _execute(self, run: dict) -> None:
        try:
            run["status"] = "running"
            self._step(run, "clone", self._open_repo, run)
            self._step(run, "discover", self._discover, run)
            self._step(run, "sbom", self._sbom, run)
            self._step(run, "vulns", self._vulns, run)
            self._step(run, "anomalies", self._anomalies, run)
            self._step(run, "graph", self._graph, run)
            self._step(run, "report", self._report, run)
            run["status"] = "done"
        except Exception as error:  # surface any failure to the UI
            run["status"] = "error"
            run["error"] = f"{type(error).__name__}: {error}"

    def _step(self, run: dict, step_id: str, func, *args) -> None:
        steps = {s["id"]: s for s in run["steps"]}
        steps[step_id]["status"] = "running"
        started = time.time()
        try:
            detail = func(*args) or ""
        except Exception:
            steps[step_id]["status"] = "error"
            raise
        steps[step_id]["status"] = "done"
        steps[step_id]["detail"] = detail
        steps[step_id]["seconds"] = round(time.time() - started, 1)

    def _open_repo(self, run: dict) -> str:
        target = self.samples_dir / run["name"]
        if target.exists() and any(target.iterdir()):
            run["repo_path"] = str(target)
            return f"reusing local clone at samples/{run['name']}"
        self.samples_dir.mkdir(parents=True, exist_ok=True)
        result = subprocess.run(
            ["git", "clone", "--depth", "1", run["url"], str(target)],
            capture_output=True, text=True, timeout=900,
        )
        if result.returncode != 0:
            raise ScanError(f"git clone failed: {result.stderr.strip()[:300]}")
        run["repo_path"] = str(target)
        return f"cloned {run['url']} (shallow)"

    def _discover(self, run: dict) -> str:
        run_dir = Path(run["run_dir"])
        run_dir.mkdir(parents=True, exist_ok=True)
        inventory = discover(run["repo_path"])
        inventory_dict = inventory.to_dict()
        import json
        (run_dir / "inventory.json").write_text(
            json.dumps(inventory_dict, indent=2), encoding="utf-8"
        )
        stats = inventory_dict["stats"]
        return (f"{stats['total']} components "
                f"({stats['direct']} direct, {stats['transitive']} transitive)")

    def _sbom(self, run: dict) -> str:
        import json
        run_dir = Path(run["run_dir"])
        inventory = json.loads((run_dir / "inventory.json").read_text(encoding="utf-8"))
        sbom = generate_cyclonedx(inventory)
        (run_dir / "sbom.cdx.json").write_text(json.dumps(sbom, indent=2), encoding="utf-8")
        return f"CycloneDX 1.5, {len(sbom.get('components', []))} components, {run_dir.name}"

    def _vulns(self, run: dict) -> str:
        import json
        from trustchain.scan.correlate import scan_vulnerabilities

        run_dir = Path(run["run_dir"])
        # shared OSV cache: re-scans and re-runs hit disk, not the API
        cache_dir = self.outputs_dir / ".osv-cache"
        inventory = json.loads((run_dir / "inventory.json").read_text(encoding="utf-8"))
        findings = scan_vulnerabilities(inventory, cache_dir=cache_dir)
        (run_dir / "vulnerabilities.json").write_text(
            json.dumps(findings, indent=2), encoding="utf-8"
        )
        by_severity: dict[str, int] = {}
        for finding in findings:
            by_severity[finding["severity"]] = by_severity.get(finding["severity"], 0) + 1
        return f"{len(findings)} findings (" + ", ".join(
            f"{count} {sev.lower()}" for sev, count in sorted(by_severity.items())
        ) + ")"

    def _anomalies(self, run: dict) -> str:
        import json

        run_dir = Path(run["run_dir"])
        inventory = json.loads((run_dir / "inventory.json").read_text(encoding="utf-8"))
        anomalies = scan_anomalies(run["repo_path"], inventory)
        (run_dir / "anomalies.json").write_text(json.dumps(anomalies, indent=2), encoding="utf-8")
        by_type: dict[str, int] = {}
        for finding in anomalies:
            by_type[finding["anomaly"]] = by_type.get(finding["anomaly"], 0) + 1
        return f"{len(anomalies)} anomalies (" + (
            ", ".join(f"{count} {label}" for label, count in sorted(by_type.items())) or "none"
        ) + ")"

    def _graph(self, run: dict) -> str:
        import json

        from trustchain.graph import render_html
        from trustchain.web.graph_json import build_graph_payload

        run_dir = Path(run["run_dir"])
        inventory = json.loads((run_dir / "inventory.json").read_text(encoding="utf-8"))
        vulnerabilities = []
        vuln_file = run_dir / "vulnerabilities.json"
        if vuln_file.exists():
            vulnerabilities = json.loads(vuln_file.read_text(encoding="utf-8"))
        highlight = {f["component"] for f in vulnerabilities}

        graph = build_graph(inventory)
        payload = build_graph_payload(graph, highlight, max_nodes=250)
        (run_dir / "graph.json").write_text(json.dumps(payload), encoding="utf-8")
        render_html(graph, run_dir / "graph.html", highlight=highlight)
        return f"{payload['stats']['total_nodes']} nodes, {payload['stats']['total_edges']} edges"

    def _report(self, run: dict) -> str:
        from trustchain.agents.client import GeminiClient
        from trustchain.agents.orchestrator import build_report_data
        from trustchain.report.render import render_report

        client = None
        note = "tools-only report (no Gemini keys in .env)"
        try:
            client = GeminiClient()
        except RuntimeError:
            client = None
        try:
            report = build_report_data(run["run_dir"], client=client)
            if client is not None:
                note = f"Gemini agents active ({client.model}, {client.key_count} keys)"
        except RuntimeError as error:
            # agent call failed (e.g. all keys rate limited) — degrade to tools-only
            report = build_report_data(run["run_dir"], client=None)
            note = f"tools-only report ({error})"
        render_report(report, Path(run["run_dir"]))
        stats = report["findings"]["stats"]
        return (f"{stats['total']} evidence entries "
                f"({stats['verified']} verified, {stats['inferred']} inferred) — {note}")
