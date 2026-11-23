"""Dependency diffing: compare two inventories (e.g. before/after a commit)
and surface unexpected supply chain changes."""

from datetime import datetime, timezone


def diff_inventories(before: dict, after: dict) -> list[dict]:
    """Returns findings for added/removed/changed components between two
    inventory snapshots (as produced by Inventory.to_dict())."""
    before_comps = {c["key"]: c for c in before["components"]}
    after_comps = {c["key"]: c for c in after["components"]}
    findings = []

    for key, comp in after_comps.items():
        if key not in before_comps:
            findings.append({
                "type": "anomaly",
                "anomaly": "dependency-added",
                "component": key,
                "component_name": comp["name"],
                "version": comp["version"],
                "detail": f"Dependency '{comp['name']}@{comp['version']}' was introduced in this change.",
                "severity": "LOW",
                "verified": True,
                "evidence": {
                    "kind": "inventory-diff",
                    "change": "added",
                    "before_ref": before.get("target", ""),
                    "after_ref": after.get("target", ""),
                    "detected_at": datetime.now(timezone.utc).isoformat(),
                },
            })

    for key in before_comps:
        if key not in after_comps:
            comp = before_comps[key]
            findings.append({
                "type": "anomaly",
                "anomaly": "dependency-removed",
                "component": key,
                "component_name": comp["name"],
                "version": comp["version"],
                "detail": f"Dependency '{comp['name']}@{comp['version']}' was removed in this change.",
                "severity": "INFO",
                "verified": True,
                "evidence": {
                    "kind": "inventory-diff",
                    "change": "removed",
                    "before_ref": before.get("target", ""),
                    "after_ref": after.get("target", ""),
                    "detected_at": datetime.now(timezone.utc).isoformat(),
                },
            })

    before_by_name: dict[tuple[str, str], list[dict]] = {}
    for comp in before_comps.values():
        before_by_name.setdefault((comp["ecosystem"], comp["name"]), []).append(comp)
    for comp in after_comps.values():
        group = before_by_name.get((comp["ecosystem"], comp["name"]), [])
        previous = next(
            (old for old in group if old["key"] != comp["key"] and old["version"] != comp["version"]),
            None,
        )
        if previous is not None:
            direction = _version_direction(previous["version"], comp["version"])
            findings.append({
                "type": "anomaly",
                "anomaly": "dependency-version-changed",
                "component": comp["key"],
                "component_name": comp["name"],
                "version": comp["version"],
                "detail": (
                    f"'{comp['name']}' changed {previous['version']} -> {comp['version']} "
                    f"({direction}). Version changes can alter transitive dependency trees."
                ),
                "severity": "LOW" if direction == "upgrade" else "MEDIUM",
                "verified": True,
                "evidence": {
                    "kind": "inventory-diff",
                    "change": "version-changed",
                    "previous_version": previous["version"],
                    "before_ref": before.get("target", ""),
                    "after_ref": after.get("target", ""),
                    "detected_at": datetime.now(timezone.utc).isoformat(),
                },
            })
    return findings


def _version_direction(old: str, new: str) -> str:
    def parse(v: str) -> tuple[int, ...]:
        return tuple(int(p) for p in v.replace("-", ".").split(".") if p.isdigit()) or (0,)
    if parse(new) > parse(old):
        return "upgrade"
    if parse(new) < parse(old):
        return "downgrade"
    return "lateral"
