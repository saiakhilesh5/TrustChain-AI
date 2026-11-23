"""yarn.lock parsers: classic (v1) and Berry (v2+) lockfile formats."""

import re
from pathlib import Path

from trustchain.discovery.models import Component, Inventory

_BERRY_ENTRY = re.compile(r'^("?)(?P<key>[^"\n]+?)\1:\s*$')


def parse_yarn_lock(path: Path, inventory: Inventory, direct_names: set[str]) -> None:
    """Parse a yarn.lock file, supporting both v1 and Berry formats."""
    rel = str(path)
    inventory.manifests.append({"type": "yarn-lock", "path": rel})
    text = path.read_text(encoding="utf-8")
    if text.lstrip().startswith("# This file is generated") and "__metadata:" in text[:200]:
        _parse_berry(text, rel, inventory, direct_names)
    else:
        _parse_v1(text, rel, inventory, direct_names)


def _parse_berry(text: str, rel: str, inventory: Inventory, direct_names: set[str]) -> None:
    entries: dict[str, dict] = {}  # "name@range" segment -> entry
    current: dict | None = None
    for line in text.splitlines():
        if not line or line.startswith("#"):
            current = None if line.strip() == "" else current
            continue
        match = _BERRY_ENTRY.match(line)
        if match and not line.startswith("  "):
            if match["key"] == "__metadata":
                current = None
                continue
            segments = [s.strip() for s in match["key"].split(",")]
            current = {"segments": segments, "version": "", "checksum": "", "dependencies": {}}
            for seg in segments:
                entries[seg] = current
            continue
        if current is None:
            continue
        stripped = line.strip()
        if stripped.startswith("version:"):
            current["version"] = stripped.split(":", 1)[1].strip()
        elif stripped.startswith("checksum:"):
            current["checksum"] = stripped.split(":", 1)[1].strip()
        elif stripped.startswith("dependencies:"):
            continue
        elif ":" in stripped and not stripped.startswith("-"):
            dep_name, dep_spec = stripped.split(":", 1)
            dep_name = dep_name.strip().strip('"')
            dep_spec = dep_spec.strip().strip('"')
            if dep_name and dep_spec:
                current["dependencies"][dep_name] = dep_spec

    # First pass: register components
    for entry in {id(e): e for e in entries.values()}.values():
        name = _v1_name(entry["segments"][0])
        version = entry["version"]
        if not version:
            continue
        scope = "direct" if name in direct_names else "transitive"
        entry["component"] = inventory.add(
            Component(
                ecosystem="npm",
                name=name,
                version=version,
                scope=scope,
                origin_path=rel,
                integrity=entry["checksum"],
                depends_on=entry["dependencies"],
            )
        )

    # Second pass: resolve dependency edges via exact "name@npm:range" segments
    for entry in {id(e): e for e in entries.values()}.values():
        component = entry.get("component")
        if component is None:
            continue
        for dep_name, dep_spec in entry["dependencies"].items():
            dep_entry = entries.get(f"{dep_name}@{dep_spec}")
            if dep_entry is not None and dep_entry.get("component") is not None:
                dep_key = dep_entry["component"].key
                if dep_key not in component.resolved_deps:
                    component.resolved_deps.append(dep_key)


def _parse_v1(text: str, rel: str, inventory: Inventory, direct_names: set[str]) -> None:
    entries: dict[str, dict] = {}
    current: dict | None = None
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if not line.startswith("  "):
            # header: '"name@range", "name2@range2":' or 'name@range, name2@range:'
            header = stripped.rstrip(":").replace('"', "")
            segments = [s.strip() for s in header.split(",")]
            current = {"segments": segments, "version": "", "integrity": "", "dependencies": {}}
            for seg in segments:
                entries[seg] = current
            continue
        if current is None:
            continue
        if stripped.startswith("version "):
            current["version"] = stripped.split(None, 1)[1].strip().replace('"', "")
        elif stripped.startswith("integrity "):
            current["integrity"] = stripped.split(None, 1)[1].strip()
        elif stripped.startswith("resolved "):
            current["resolved"] = stripped.split(None, 1)[1].strip()
        elif " " in stripped and not stripped.startswith("#"):
            dep_name, dep_spec = stripped.split(None, 1)
            current["dependencies"][dep_name.strip('"')] = dep_spec.strip().replace('"', "")

    for entry in {id(e): e for e in entries.values()}.values():
        name = _v1_name(entry["segments"][0])
        version = entry.get("version", "")
        if not version:
            continue
        scope = "direct" if name in direct_names else "transitive"
        entry["component"] = inventory.add(
            Component(
                ecosystem="npm",
                name=name,
                version=version,
                scope=scope,
                origin_path=rel,
                resolved_url=entry.get("resolved", ""),
                integrity=entry.get("integrity", ""),
                depends_on=entry.get("dependencies", {}),
            )
        )

    for entry in {id(e): e for e in entries.values()}.values():
        component = entry.get("component")
        if component is None:
            continue
        for dep_name, dep_spec in entry.get("dependencies", {}).items():
            dep_entry = entries.get(f"{dep_name}@{dep_spec}")
            if dep_entry is not None and dep_entry.get("component") is not None:
                dep_key = dep_entry["component"].key
                if dep_key not in component.resolved_deps:
                    component.resolved_deps.append(dep_key)


def _v1_name(segment: str) -> str:
    """Extract package name from 'name@range' (handles @scoped names)."""
    if segment.startswith("@"):
        return "@" + segment[1:].split("@", 1)[0]
    return segment.split("@", 1)[0]
