import json

from trustchain.agents.anomaly_investigator import analyze_anomalies
from trustchain.agents.client import extract_json
from trustchain.agents.orchestrator import build_report_data
from trustchain.agents.vuln_analyst import analyze_vulnerabilities
from trustchain.evidence.store import EvidenceStore


class FakeLlm:
    """Returns a canned, id-keyed JSON response."""

    model = "fake-model"

    def __init__(self, response: str):
        self.response = response

    def complete(self, system, user, max_tokens=4096):
        return self.response


def test_evidence_store_ingest_and_stats():
    store = EvidenceStore(run_id="r1", target="app")
    store.ingest([
        {"type": "vulnerability", "severity": "HIGH", "component": "npm:x@1"},
        {"type": "anomaly", "severity": "MEDIUM", "component": "y", "verified": False},
    ], source="test")
    data = store.to_dict()
    assert data["stats"]["total"] == 2
    assert data["stats"]["verified"] == 1
    assert data["stats"]["inferred"] == 1
    assert data["entries"][0]["id"] == "T-0001"
    assert data["entries"][1]["id"] == "T-0002"


def test_extract_json_from_wrapped_response():
    text = 'Here is my analysis:\n```json\n{"analyses": {"T-0001": {"risk_level": "high"}}}\n```\nDone.'
    assert extract_json(text) == {"analyses": {"T-0001": {"risk_level": "high"}}}


def test_vuln_analyst_discards_unknown_ids():
    findings = [{"id": "T-0001", "component": "npm:x@1", "severity": "HIGH"}]
    fake = FakeLlm(json.dumps({"analyses": {
        "T-0001": {"risk_level": "high", "attention_reason": "direct dep", "confidence": "high"},
        "T-9999": {"risk_level": "critical"},  # hallucinated id — must be discarded
    }}))
    result = analyze_vulnerabilities(fake, findings)
    assert "T-0001" in result
    assert "T-9999" not in result


def test_anomaly_investigator_analyzes_all():
    findings = [{"id": "T-0002", "anomaly": "possible-typosquat", "severity": "HIGH",
                 "component": "color", "detail": "d", "evidence": {}}]
    fake = FakeLlm(json.dumps({"analyses": {
        "T-0002": {"verdict": "needs-review", "reasoning": "r",
                   "recommended_action": "verify provenance", "confidence": "medium"},
    }}))
    result = analyze_anomalies(fake, findings)
    assert result["T-0002"]["verdict"] == "needs-review"


def test_orchestrator_builds_report(tmp_path):
    inventory = {"target": "app", "stats": {"total": 2, "direct": 1, "transitive": 1},
                 "components": []}
    (tmp_path / "inventory.json").write_text(json.dumps(inventory), encoding="utf-8")
    (tmp_path / "vulnerabilities.json").write_text(json.dumps([
        {"type": "vulnerability", "component": "npm:x@1", "component_name": "x",
         "version": "1", "severity": "HIGH", "cve": "CVE-1", "fixed_versions": ["1.1"]},
    ]), encoding="utf-8")
    (tmp_path / "anomalies.json").write_text(json.dumps([]), encoding="utf-8")

    fake = FakeLlm(json.dumps({"analyses": {"T-0001": {
        "risk_level": "high", "attention_reason": "used directly",
        "reachability_note": "single path", "confidence": "high",
    }}}))
    report = build_report_data(tmp_path, client=fake)
    assert report["findings"]["stats"]["total"] == 1
    entry = report["findings"]["entries"][0]
    assert entry["ai_analysis"]["risk_level"] == "high"
    assert (tmp_path / "evidence.json").exists()

    from trustchain.report.render import render_report
    html_path, json_path = render_report(report, tmp_path)
    assert html_path.exists() and json_path.exists()
    html = html_path.read_text(encoding="utf-8")
    assert "TrustChain-AI Guardian Report" in html
    assert "used directly" in html
    assert "inference, not verified evidence" in html


def test_orchestrator_offline_mode(tmp_path):
    (tmp_path / "inventory.json").write_text(json.dumps({"target": "app", "stats": {}, "components": []}), encoding="utf-8")
    (tmp_path / "vulnerabilities.json").write_text("[]", encoding="utf-8")
    (tmp_path / "anomalies.json").write_text("[]", encoding="utf-8")
    report = build_report_data(tmp_path, client=None)
    assert report["agent_summary"]["agent_model"].startswith("offline")
    assert report["findings"]["stats"]["total"] == 0
