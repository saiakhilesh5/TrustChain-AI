"""Vulnerability Analyst agent: prioritizes which CVE findings matter.

Input: verified vulnerability findings with dependency paths.
Output (JSON): per finding id — initial risk level, why it matters,
what makes it urgent or ignorable, confidence. Pure reasoning; the
agent cannot add or remove findings, only annotate them.
"""

from trustchain.agents.client import LlmClient, extract_json

SYSTEM_PROMPT = """You are the Vulnerability Analyst of TrustChain-AI, a software
supply chain guardian. You receive verified vulnerability findings as JSON.
Each finding already has: component, version, CVE, severity, fixed versions,
and dependency paths (how the application reaches the component).

Your job is to reason about which findings actually deserve attention, by
combining severity with exposure and reachability signals present in the data:

- A component with many dependency paths is widely used -> higher attention.
- A component reached directly by the application is more exposed than one
  reached only through dev/build tooling.
- A version like "0.0.0-use.local" indicates a local workspace package, not a
  registry dependency: upgrading it means changing the application itself, not
  bumping a lockfile entry.
- If a fixed version exists, remediation is easier -> note it.

Rules you MUST follow:
- Respond with a single JSON object: {"analyses": {"<finding id>": {...}, ...}}.
- Only use finding ids exactly as given. Never invent ids, CVEs, or components.
- Base every statement on the provided data. If data is missing, say so.
- Keep each explanation under 60 words, plain language, no speculation
  presented as fact. Mark uncertainty with a lower confidence value.

For each finding provide:
  "risk_level": one of "critical", "high", "medium", "low"
  "attention_reason": why this does or does not need attention now
  "reachability_note": what the dependency paths imply about exposure
  "confidence": one of "high", "medium", "low"
"""


BATCH_SIZE = 25


def analyze_vulnerabilities(client: LlmClient, findings: list[dict]) -> dict:
    if not findings:
        return {}
    analyses = {}
    valid_ids = {f["id"] for f in findings}
    for start in range(0, len(findings), BATCH_SIZE):
        chunk = findings[start : start + BATCH_SIZE]
        payload = [
            {
                "id": f["id"],
                "component": f["component"],
                "cve": f.get("cve", f.get("advisory_id", "")),
                "severity": f["severity"],
                "fixed_versions": f.get("fixed_versions", []),
                "dependency_paths": f.get("dependency_paths", [])[:3],
            }
            for f in chunk
        ]
        user = f"Analyze these findings (batch {start // BATCH_SIZE + 1}):\n" + _dumps(payload)
        try:
            response = client.complete(SYSTEM_PROMPT, user, max_tokens=8000)
            result = extract_json(response)
        except (ValueError, RuntimeError):
            # malformed or truncated agent output — keep tool-verified facts only
            continue
        for key, value in result.get("analyses", {}).items():
            if key in valid_ids:
                analyses[key] = value
    return analyses


def _dumps(data) -> str:
    import json

    return json.dumps(data, indent=2)
