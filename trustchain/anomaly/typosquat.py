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

MAX_EDIT_DISTANCE = 2
MIN_NAME_LENGTH = 5


def scan_typosquats(inventory: dict) -> list[dict]:
    """Flag components whose names are small edit-distance duplicates of
    popular packages without being equal to them."""
    findings = []
    seen = set()
    for comp in inventory["components"]:
        name = comp["name"]
        if comp["ecosystem"] != "npm" or name in seen or name in POPULAR_PACKAGES:
            continue
        if len(name) < MIN_NAME_LENGTH:
            continue
        seen.add(name)
        closest = _closest(name)
        if closest is None:
            continue
        popular, distance, ratio = closest
        findings.append({
            "type": "anomaly",
            "anomaly": "possible-typosquat",
            "component": comp["key"],
            "component_name": name,
            "version": comp["version"],
            "detail": (
                f"Package name '{name}' is edit-distance {distance} from popular "
                f"package '{popular}' but is not the same package. Typosquatting is a "
                f"common supply chain attack vector; verify provenance before trusting it."
            ),
            "severity": "HIGH" if distance == 1 else "MEDIUM",
            "verified": False,  # similarity is fact; "typosquat" is an inference
            "inference": {
                "confidence": "medium" if distance == 1 else "low",
                "reasoning": "Name similarity is measured deterministically, but intent can only be judged with provenance and maintainer context.",
            },
            "evidence": {
                "kind": "name-similarity",
                "edit_distance": distance,
                "similarity": round(ratio, 3),
                "similar_to": popular,
                "dependency_paths": comp.get("required_by", [])[:3],
            },
        })
    return findings


def _closest(name: str) -> tuple[str, int, float] | None:
    best: tuple[str, int, float] | None = None
    for popular in POPULAR_PACKAGES:
        if name == popular:
            continue
        distance = _levenshtein(name, popular)
        if distance > MAX_EDIT_DISTANCE:
            continue
        ratio = SequenceMatcher(None, name, popular).ratio()
        if best is None or distance < best[1]:
            best = (popular, distance, ratio)
    return best


def _levenshtein(a: str, b: str) -> int:
    if abs(len(a) - len(b)) > MAX_EDIT_DISTANCE:
        return MAX_EDIT_DISTANCE + 1
    previous = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        current = [i]
        for j, cb in enumerate(b, 1):
            current.append(min(
                previous[j] + 1,
                current[j - 1] + 1,
                previous[j - 1] + (ca != cb),
            ))
        previous = current
    return previous[-1]
