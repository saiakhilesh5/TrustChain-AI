"""npm ecosystem parsers: package.json (direct deps) and package-lock.json (full tree)."""

import json
from pathlib import Path

from trustchain.discovery.models import Component, Inventory


def parse_package_json(path: Path, inventory: Inventory) -> list[str]:
    """Register a workspace package and return its declared dependency names."""
    data = json.loads(path.read_text(encoding="utf-8"))
    rel = str(path)
    inventory.manifests.append({"type": "npm-package", "path": rel})

    component = Component(
        ecosystem="npm",
        name=data.get("name", path.parent.name),
        version=data.get("version", "0.0.0"),
        scope="direct",
        origin_path=rel,
        license=data.get("license", ""),
        repository_url=(data.get("repository") or {}).get("url", "")
        if isinstance(data.get("repository"), dict)
        else data.get("repository", ""),
    )
    inventory.add(component)

    dep_names = []
    for section in ("dependencies", "optionalDependencies"):
        for name, spec in (data.get(section) or {}).items():
            component.depends_on[name] = spec
            dep_names.append(name)
    return dep_names


def parse_package_lock(path: Path, inventory: Inventory, direct_names: set[str]) -> None:
    """Parse npm package-lock v2/v3: full direct + transitive tree with edges."""
    data = json.loads(path.read_text(encoding="utf-8"))
    rel = str(path)
    inventory.manifests.append({"type": "npm-lock", "path": rel})

    packages = data.get("packages", {})
    # packages maps paths like "" (root), "node_modules/x" -> package info
    path_to_key: dict[str, str] = {}
    for node_path, info in packages.items():
        if node_path == "":
            continue
        name = info.get("name") or node_path.split("node_modules/")[-1]
        version = info.get("version", "")
        if not version:
            continue
        scope = "direct" if name in direct_names else "transitive"
        component = inventory.add(
            Component(
                ecosystem="npm",
                name=name,
                version=version,
                scope=scope,
                origin_path=rel,
                resolved_url=info.get("resolved", ""),
                integrity=info.get("integrity", ""),
                license=info.get("license", ""),
            )
        )
        path_to_key[node_path] = component.key
        for dep_name, spec in (info.get("dependencies") or {}).items():
            component.depends_on[dep_name] = spec

    for node_path, key in path_to_key.items():
        component = inventory.components[key]
        info = packages[node_path]
        for dep_name in (info.get("dependencies") or {}):
            dep_key = _resolve_dep_path(node_path, dep_name, packages)
            if dep_key and dep_key in path_to_key:
                dep_component_key = path_to_key[dep_key]
                if dep_component_key not in component.resolved_deps:
                    component.resolved_deps.append(dep_component_key)


def _resolve_dep_path(node_path: str, dep_name: str, packages: dict) -> str | None:
    """npm resolves deps by walking up the node_modules tree; replicate that,
    preferring the most specific (deepest) match."""
    parts = Path(node_path).parts
    for i in range(len(parts), -1, -1):
        prefix = "/".join(parts[:i])
        candidate = f"{prefix}/node_modules/{dep_name}" if prefix else f"node_modules/{dep_name}"
        if candidate in packages:
            return candidate
    return None
