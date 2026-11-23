"""Anomaly Investigator agent: reasons about non-CVE supply chain anomalies.

Deterministic detectors cast a wide net (e.g. edit-distance typosquat
candidates). This agent separates genuinely suspicious cases from benign
near-misses using evidence present in the finding, and clearly marks its
output as inference, never as verified fact.
"""

from trustchain.agents.client import LlmClient, extract_json

SYSTEM_PROMPT = """You are the Anomaly Investigator of TrustChain-AI, a software
supply chain guardian. You receive anomaly findings produced by deterministic
detectors: unpinned CI actions, risky install scripts, unpinned container
images, and possible typosquats. Each finding carries its evidence.

Your job: judge which anomalies are genuinely suspicious and which are benign,
using only the evidence provided. Known context:

- Typosquat candidates at edit distance 1 from a popular package deserve real
  scrutiny; distance 2 is usually an unrelated legitimate package.
- CI actions owned by the same organization as the repository are lower risk
  than third-party actions, but still mutable if not SHA-pinned.
- curl|bash install scripts are a real code-execution vector regardless of
  who wrote them.

Rules you MUST follow:
- Respond with a single JSON object: {"analyses": {"<finding id>": {...}, ...}}.
- Only use finding ids exactly as given. Never invent ids or packages.
- Your output is AI INFERENCE, not verified evidence. Do not assert facts
  that are not in the data; frame judgements as judgements.
- Keep each explanation under 60 words.

For each finding provide:
  "verdict": one of "suspicious", "likely-benign", "needs-review"
  "reasoning": the evidence-based reasoning for the verdict
  "recommended_action": one short action, e.g. "pin action to commit SHA",
    "verify package provenance and maintainer", "no action needed"
  "confidence": one of "high", "medium", "low"
"""


def analyze_anomalies(client: LlmClient, findings: list[dict]) -> dict:
    if not findings:
        return {}
    payload = [
        {
            "id": f["id"],
            "anomaly": f["anomaly"],
            "component": f.get("component", ""),
            "severity": f["severity"],
            "detail": f.get("detail", ""),
            "evidence": f.get("evidence", {}),
        }
        for f in findings
    ]
    user = "Analyze these anomaly findings:\n" + _dumps(payload)
    try:
        response = client.complete(SYSTEM_PROMPT, user, max_tokens=8000)
        result = extract_json(response)
    except (ValueError, RuntimeError):
        # malformed or truncated agent output — keep tool-verified facts only
        return {}
    analyses = result.get("analyses", {})
    valid_ids = {f["id"] for f in findings}
    return {k: v for k, v in analyses.items() if k in valid_ids}


def _dumps(data) -> str:
    import json

    return json.dumps(data, indent=2)
