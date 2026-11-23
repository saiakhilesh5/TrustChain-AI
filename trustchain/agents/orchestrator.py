"""Guardian Orchestrator: coordinates the Day 1 pipeline for a completed scan.

Scan outputs (inventory, vulnerabilities, anomalies) are ingested into the
evidence ledger, then the agent layer annotates them with contextual
reasoning. Agent output is merged by finding id; unknown ids are discarded.
"""

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path

from trustchain.agents.anomaly_investigator import analyze_anomalies
from trustchain.agents.client import LlmClient, OfflineClient
from trustchain.agents.vuln_analyst import analyze_vulnerabilities
from trustchain.evidence.store import EvidenceStore


def build_report_data(run_dir: str | Path, client: LlmClient | None = None) -> dict:
    run_dir = Path(run_dir)
    inventory = _load(run_dir / "inventory.json")
    vulnerabilities = _load(run_dir / "vulnerabilities.json")
    anomalies = _load(run_dir / "anomalies.json")

    store = EvidenceStore(run_id=str(uuid.uuid4())[:8], target=inventory.get("target", ""))
    store.ingest(vulnerabilities, source="osv")
    store.ingest(anomalies, source="anomaly-detectors")

    vuln_entries = [e for e in store.entries if e.get("type") == "vulnerability"]
    anomaly_entries = [e for e in store.entries if e.get("type") == "anomaly"]

    agent_summary = {
        "agent_model": "offline (deterministic tools only)",
        "vulnerability_analyses": {},
        "anomaly_analyses": {},
    }
    if client is not None:
        agent_summary["agent_model"] = _model_name(client)
        agent_summary["vulnerability_analyses"] = analyze_vulnerabilities(client, vuln_entries)
        agent_summary["anomaly_analyses"] = analyze_anomalies(client, anomaly_entries)

    _merge_analyses(store.entries, agent_summary)

    report = {
        "title": "TrustChain-AI Guardian Report",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "target": inventory.get("target", ""),
        "inventory_stats": inventory.get("stats", {}),
        "agent_summary": agent_summary,
        "findings": store.to_dict(),
    }
    store.save(run_dir / "evidence.json")
    return report


def _merge_analyses(entries: list[dict], agent_summary: dict) -> None:
    vuln_map = agent_summary["vulnerability_analyses"]
    anomaly_map = agent_summary["anomaly_analyses"]
    for entry in entries:
        analysis = vuln_map.get(entry["id"]) or anomaly_map.get(entry["id"])
        if analysis:
            entry["ai_analysis"] = analysis
            entry.setdefault("inference", None)


def _model_name(client: LlmClient) -> str:
    return getattr(client, "model", "gemini")


def _load(path: Path) -> dict | list:
    if not path.exists():
        return [] if path.name != "inventory.json" else {}
    return json.loads(path.read_text(encoding="utf-8"))
