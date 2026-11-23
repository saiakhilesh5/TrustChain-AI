"""Flask API + static file serving for the TrustChain-AI web UI."""

import json
from pathlib import Path

from flask import Flask, jsonify, request, send_from_directory

from trustchain.web.checklist import build_checklist
from trustchain.web.runner import RunManager, ScanError

STATIC_DIR = Path(__file__).resolve().parent / "static"


def create_app(base_dir: str | Path | None = None) -> Flask:
    app = Flask(__name__, static_folder=None)
    manager = RunManager(base_dir)

    @app.get("/")
    def index():
        return send_from_directory(STATIC_DIR, "index.html")

    @app.get("/api/health")
    def health():
        return jsonify({"ok": True, "version": "1.0"})

    @app.post("/api/scan")
    def start_scan():
        payload = request.get_json(silent=True) or {}
        url = (payload.get("url") or "").strip()
        if not url:
            return jsonify({"error": "missing 'url'"}), 400
        try:
            run = manager.start(url)
        except ScanError as error:
            return jsonify({"error": str(error)}), 400
        return jsonify(run), 202

    @app.get("/api/runs")
    def list_runs():
        return jsonify([
            {
                "id": run["id"], "url": run["url"], "name": run["name"],
                "status": run["status"], "created_at": run["created_at"],
                "completed_steps": sum(1 for s in run["steps"] if s["status"] == "done"),
                "total_steps": len(run["steps"]),
            }
            for run in manager.list_runs()
        ])

    @app.get("/api/runs/<run_id>")
    def run_status(run_id: str):
        run = manager.get(run_id)
        if run is None:
            return _disk_run(run_id, manager)
        return jsonify(run)

    @app.get("/api/runs/<run_id>/checklist")
    def run_checklist(run_id: str):
        run_dir, error = _resolve(run_id, manager)
        if error:
            return error
        run = manager.get(run_id)
        return jsonify(build_checklist(run_dir, run["steps"] if run else None))

    @app.get("/api/runs/<run_id>/inventory")
    def run_inventory(run_id: str):
        run_dir, error = _resolve(run_id, manager)
        if error:
            return error
        data = _read_json(run_dir / "inventory.json", default={})
        query = (request.args.get("search") or "").lower()
        components = data.get("components", [])
        if query:
            components = [c for c in components if query in c.get("key", "").lower()]
        limit = min(int(request.args.get("limit", 200)), 2000)
        return jsonify({
            "target": data.get("target"),
            "stats": data.get("stats", {}),
            "components": components[:limit],
            "shown": min(len(components), limit),
            "matches": len(components),
        })

    @app.get("/api/runs/<run_id>/vulnerabilities")
    def run_vulnerabilities(run_id: str):
        run_dir, error = _resolve(run_id, manager)
        if error:
            return error
        findings = _read_json(run_dir / "vulnerabilities.json", default=[])
        by_severity: dict[str, int] = {}
        for finding in findings:
            by_severity[finding.get("severity", "?")] = by_severity.get(finding.get("severity", "?"), 0) + 1
        severity = request.args.get("severity")
        if severity:
            findings = [f for f in findings if f.get("severity") == severity.upper()]
        return jsonify({"total": len(findings), "by_severity": by_severity, "findings": findings})

    @app.get("/api/runs/<run_id>/anomalies")
    def run_anomalies(run_id: str):
        run_dir, error = _resolve(run_id, manager)
        if error:
            return error
        findings = _read_json(run_dir / "anomalies.json", default=[])
        return jsonify({"total": len(findings), "findings": findings})

    @app.get("/api/runs/<run_id>/graph")
    def run_graph(run_id: str):
        run_dir, error = _resolve(run_id, manager)
        if error:
            return error
        payload = _read_json(run_dir / "graph.json", default=None)
        if payload is None:
            return jsonify({"error": "graph not built yet"}), 404
        return jsonify(payload)

    @app.get("/api/runs/<run_id>/report")
    def run_report(run_id: str):
        run_dir, error = _resolve(run_id, manager)
        if error:
            return error
        report = _read_json(run_dir / "guardian_report.json", default=None)
        if report is None:
            return jsonify({"error": "report not generated yet"}), 404
        return jsonify(report)

    @app.get("/api/runs/<run_id>/report.html")
    def run_report_html(run_id: str):
        run_dir, error = _resolve(run_id, manager)
        if error:
            return error
        html = run_dir / "guardian_report.html"
        if not html.exists():
            return jsonify({"error": "report not generated yet"}), 404
        return send_from_directory(run_dir, "guardian_report.html")

    @app.get("/api/runs/<run_id>/artifacts/<filename>")
    def run_artifact(run_id: str, filename: str):
        run_dir, error = _resolve(run_id, manager)
        if error:
            return error
        if "/" in filename or ".." in filename:
            return jsonify({"error": "invalid filename"}), 400
        path = run_dir / filename
        if not path.exists():
            return jsonify({"error": "not found"}), 404
        return send_from_directory(run_dir, filename)

    def _resolve(run_id: str, mgr: RunManager):
        run = mgr.get(run_id)
        if run is not None:
            return Path(run["run_dir"]), None
        run_dir = mgr.outputs_dir / run_id
        if (run_dir / "inventory.json").exists():
            return run_dir, None
        return None, (jsonify({"error": "unknown run"}), 404)

    def _disk_run(run_id: str, mgr: RunManager):
        run_dir, error = _resolve(run_id, mgr)
        if error:
            return error
        return jsonify({
            "id": run_id, "url": "", "name": run_id, "status": "done",
            "steps": [], "error": None, "run_dir": str(run_dir),
        })

    return app


def _read_json(path: Path, default):
    if not path.exists():
        return default
    return json.loads(path.read_text(encoding="utf-8"))


def main(host: str = "127.0.0.1", port: int = 5000) -> None:
    from trustchain.env import load_env

    load_env()
    app = create_app()
    print(f"TrustChain-AI web UI: http://{host}:{port}")
    app.run(host=host, port=port, debug=False, threaded=True)
