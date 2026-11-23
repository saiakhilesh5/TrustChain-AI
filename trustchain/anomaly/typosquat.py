"""Typosquat detection: component names suspiciously similar to popular packages."""

from difflib import SequenceMatcher

# high-traffic npm/PyPI names most frequently targeted by typosquatters
POPULAR_PACKAGES = [
    "npm", "node", "chalk", "request", "lodash", "async", "moment", "express",
    "react", "vue", "axios", "commander", "debug", "ms", "uuid", "minimist",
    "colors", "cross-env", "typescript", "jest", "eslint", "webpack", "babel",
    "jquery", "bootstrap", "left-pad", "event-stream", "ua-parser-js", "coa",
    "rc", "node-ipc", "peerid", "psl", "tar", "ini", "path-parse",
    "flask", "django", "requests", "urllib3", "pillow", "numpy", "pandas",
    "sqlalchemy", "pyyaml", "jinja2", "crypto", "cryptograph",
]

SIMILARITY_THRESHOLD = 0.86


def scan_typosquats(inventory: dict) -> list[dict]:
    """Flag components whose names are near-duplicates of popular packages
    without being equal to them."""
    findings = []
    seen = set()
    for comp in inventory["components"]:
        name = comp["name"]
        if comp["ecosystem"] != "npm" or name in seen or name in POPULAR_PACKAGES:
            continue
        seen.add(name)
        best_name, best_ratio = _closest(name)
        if best_ratio >= SIMILARITY_THRESHOLD:
            findings.append({
                "type": "anomaly",
                "anomaly": "possible-typosquat",
                "component": comp["key"],
                "component_name": name,
                "version": comp["version"],
                "detail": (
                    f"Package name '{name}' is {(best_ratio * 100):.0f}% similar to popular "
                    f"package '{best_name}' but is not the same package. Typosquatting is a "
                    f"common supply chain attack vector; verify provenance before trusting it."
                ),
                "severity": "HIGH",
                "verified": False,  # similarity is fact; "typosquat" is an inference
                "inference": {
                    "confidence": "medium",
                    "reasoning": "Name similarity is measured deterministically, but intent can only be judged with provenance and maintainer context.",
                },
                "evidence": {
                    "kind": "name-similarity",
                    "similarity": round(best_ratio, 3),
                    "similar_to": best_name,
                    "dependency_paths": comp.get("required_by", [])[:3],
                },
            })
    return findings


def _closest(name: str) -> tuple[str, float]:
    best_name, best_ratio = "", 0.0
    for popular in POPULAR_PACKAGES:
        if name == popular:
            continue
        ratio = SequenceMatcher(None, name, popular).ratio()
        if ratio > best_ratio:
            best_name, best_ratio = popular, ratio
    return best_name, best_ratio
