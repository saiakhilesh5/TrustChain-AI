"""Guardian report rendering: human-readable HTML + machine-readable JSON."""

import json
from pathlib import Path

from jinja2 import StrictUndefined, Template

TEMPLATE = Template("""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>{{ report.title }} — {{ report.target }}</title>
<style>
  :root { --bg:#0f172a; --card:#1e293b; --text:#e2e8f0; --muted:#94a3b8; --accent:#38bdf8; }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: var(--bg); color: var(--text); font: 15px/1.55 'Segoe UI', system-ui, sans-serif; padding: 40px 24px; }
  .wrap { max-width: 1080px; margin: 0 auto; }
  h1 { font-size: 26px; margin-bottom: 4px; }
  h2 { font-size: 19px; margin: 36px 0 14px; color: var(--accent); border-bottom: 1px solid #334155; padding-bottom: 8px; }
  .sub { color: var(--muted); margin-bottom: 24px; }
  .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 12px; margin: 20px 0; }
  .stat { background: var(--card); border-radius: 10px; padding: 16px; text-align: center; }
  .stat b { display: block; font-size: 26px; }
  .stat span { color: var(--muted); font-size: 12px; text-transform: uppercase; letter-spacing: .06em; }
  .badge { display: inline-block; padding: 2px 10px; border-radius: 999px; font-size: 12px; font-weight: 600; }
  .CRITICAL { background:#7f1d1d; } .HIGH { background:#9a3412; } .MEDIUM, .MODERATE { background:#78350f; }
  .LOW { background:#1e3a5f; } .INFO, .UNKNOWN { background:#334155; }
  .card { background: var(--card); border-radius: 10px; padding: 16px 18px; margin: 10px 0; }
  .card .head { display: flex; gap: 10px; align-items: center; flex-wrap: wrap; margin-bottom: 6px; }
  .card .id { color: var(--muted); font-family: ui-monospace, monospace; font-size: 12px; }
  .card .comp { font-weight: 600; font-family: ui-monospace, monospace; }
  .card .detail { color: #cbd5e1; font-size: 14px; margin: 6px 0; }
  .path { font-family: ui-monospace, monospace; font-size: 12.5px; color: #7dd3fc; background: #0b1120; border-radius: 6px; padding: 6px 10px; margin: 6px 0; overflow-wrap: anywhere; }
  .ai { border-left: 3px solid var(--accent); padding: 8px 12px; margin: 8px 0; background: #0b1120; border-radius: 0 6px 6px 0; font-size: 13.5px; }
  .ai .tag { color: var(--accent); font-size: 11px; text-transform: uppercase; letter-spacing: .08em; font-weight: 700; }
  .evi { font-size: 12.5px; color: var(--muted); font-family: ui-monospace, monospace; overflow-wrap: anywhere; }
  details { margin: 8px 0; } summary { cursor: pointer; color: var(--muted); }
  .note { background: #14532d33; border: 1px solid #166534; border-radius: 10px; padding: 16px 18px; font-size: 14px; }
  footer { margin-top: 40px; color: var(--muted); font-size: 12px; text-align: center; }
  a { color: var(--accent); }
</style>
</head>
<body><div class="wrap">

<h1>{{ report.title }}</h1>
<div class="sub">Target: <b>{{ report.target }}</b> &nbsp;·&nbsp; Generated {{ report.generated_at[:19] }} UTC &nbsp;·&nbsp; Agent: {{ report.agent_summary.agent_model }}</div>

<div class="grid">
  <div class="stat"><b>{{ report.inventory_stats.total }}</b><span>components</span></div>
  <div class="stat"><b>{{ report.inventory_stats.direct }}</b><span>direct deps</span></div>
  <div class="stat"><b>{{ report.inventory_stats.transitive }}</b><span>transitive</span></div>
  <div class="stat"><b>{{ findings.stats.total }}</b><span>findings</span></div>
  <div class="stat"><b>{{ findings.stats.verified }}</b><span>verified</span></div>
  <div class="stat"><b>{{ findings.stats.inferred }}</b><span>ai-inferred</span></div>
</div>

<h2>Top risks</h2>
{% for entry in top_risks %}
<div class="card">
  <div class="head">
    <span class="badge {{ entry.severity }}">{{ entry.severity }}</span>
    <span class="comp">{{ entry.get('component_name') or entry.component }}</span>
    {% if entry.get('cve') %}<span class="badge INFO">{{ entry.get('cve') }}</span>{% endif %}
    {% if entry.get('anomaly') %}<span class="badge INFO">{{ entry.get('anomaly') }}</span>{% endif %}
    <span class="id">{{ entry.id }} · {{ entry.source }}</span>
  </div>
  <div class="detail">{{ entry.get('detail') or entry.get('summary') }}</div>
  {% for path in (entry.get('dependency_paths') or [])[:2] %}
    <div class="path">{{ " → ".join(path) }}</div>
  {% endfor %}
  {% if entry.get('fixed_versions') %}
    <div class="evi">fix available: {{ entry.get('fixed_versions')|join(", ") }}</div>
  {% endif %}
  {% if entry.get('evidence', {}).get('path') %}
    <div class="evi">evidence: {{ entry.get('evidence', {}).get('path') }}{% if entry.get('evidence', {}).get('line') %}:{{ entry.get('evidence', {}).get('line') }}{% endif %} — {{ entry.get('evidence', {}).get('content', '')[:120] }}</div>
  {% elif entry.get('evidence', {}).get('advisory_url') %}
    <div class="evi">evidence: <a href="{{ entry.get('evidence', {}).get('advisory_url') }}">{{ entry.get('evidence', {}).get('advisory_url') }}</a> (OSV.dev)</div>
  {% endif %}
  {% if entry.get('ai_analysis') %}
  <div class="ai"><span class="tag">AI analysis — inference, not verified evidence</span><br>
    {{ entry.ai_analysis.attention_reason or entry.ai_analysis.reasoning }}
    {% if entry.ai_analysis.reachability_note %}<br><i>{{ entry.ai_analysis.reachability_note }}</i>{% endif %}
    <br>verdict: <b>{{ entry.ai_analysis.risk_level or entry.ai_analysis.verdict or "n/a" }}</b> · confidence: {{ entry.ai_analysis.confidence }}
  </div>
  {% endif %}
</div>
{% endfor %}

<h2>All findings</h2>
<details open>
  <summary>Vulnerabilities ({{ vuln_count }})</summary>
  {% for entry in vuln_findings %}
  <div class="card">
    <div class="head">
      <span class="badge {{ entry.severity }}">{{ entry.severity }}</span>
      <span class="comp">{{ entry.get('component_name') }}@{{ entry.version }}</span>
      <span class="badge INFO">{{ entry.get('cve') }}</span>
      <span class="id">{{ entry.id }}</span>
    </div>
    {% if entry.get('ai_analysis') and loop.index <= 20 %}
    <div class="ai"><span class="tag">AI</span> {{ entry.ai_analysis.attention_reason }} ({{ entry.ai_analysis.confidence }})</div>
    {% endif %}
  </div>
  {% endfor %}
</details>
<details>
  <summary>Anomalies ({{ anomaly_count }})</summary>
  {% for entry in anomaly_findings %}
  <div class="card">
    <div class="head">
      <span class="badge {{ entry.severity }}">{{ entry.severity }}</span>
      <span class="badge INFO">{{ entry.anomaly }}</span>
      <span class="comp">{{ entry.get('component_name') or entry.component }}</span>
      <span class="id">{{ entry.id }}</span>
    </div>
    <div class="detail">{{ entry.detail }}</div>
    {% if entry.get('ai_analysis') and loop.index <= 20 %}
    <div class="ai"><span class="tag">AI</span> {{ entry.ai_analysis.reasoning }} → {{ entry.ai_analysis.recommended_action }} ({{ entry.ai_analysis.confidence }})</div>
    {% endif %}
  </div>
  {% endfor %}
</details>

<h2>Methodology &amp; evidence policy</h2>
<div class="note">
  <p><b>Verified findings</b> ({{ findings.stats.verified }}) are produced by deterministic tooling: manifest
  parsing, CycloneDX SBOM generation, OSV.dev advisory correlation, and static anomaly detectors.
  Each carries its evidence: file paths and line numbers, advisory URLs, or measured similarity values.</p>
  <p style="margin-top:8px"><b>AI-inferred findings</b> ({{ findings.stats.inferred }}) and AI analysis blocks
  are generated by Gemini agents over the verified data. Agent output is merged by finding id only —
  any id or claim not present in the tool output is discarded. AI text is always labeled as inference
  and never presented as tool-verified evidence.</p>
  <p style="margin-top:8px"><b>Human approval:</b> no remediation action is applied automatically. Day 2
  proposals are branch-only and require explicit human approval before merge.</p>
</div>

<h2>Artifacts</h2>
<div class="note">
  <a href="graph.html">Dependency graph (interactive)</a> ·
  <a href="sbom.cdx.json">CycloneDX SBOM</a> ·
  <a href="evidence.json">Evidence ledger (JSON)</a> ·
  <a href="guardian_report.json">Guardian report (machine-readable JSON)</a> ·
  <a href="inventory.json">Component inventory</a>
</div>

<footer>TrustChain-AI · Software Supply Chain Guardian · Know What You Build. Trust What You Ship.</footer>
</div></body></html>
""", undefined=StrictUndefined)


def render_report(report: dict, output_dir: Path) -> tuple[Path, Path]:
    findings = report["findings"]
    entries = findings["entries"]

    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "MODERATE": 2, "LOW": 3, "INFO": 4, "UNKNOWN": 5}
    top = sorted(entries, key=lambda e: severity_order.get(e.get("severity", "UNKNOWN"), 5))[:25]

    vuln = [e for e in entries if e.get("type") == "vulnerability"]
    anomaly = [e for e in entries if e.get("type") == "anomaly"]

    html = TEMPLATE.render(
        report=report,
        findings=findings,
        top_risks=top,
        vuln_findings=vuln,
        vuln_count=len(vuln),
        anomaly_findings=anomaly,
        anomaly_count=len(anomaly),
    )
    html_path = output_dir / "guardian_report.html"
    html_path.write_text(html, encoding="utf-8")

    json_path = output_dir / "guardian_report.json"
    json_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    return html_path, json_path
