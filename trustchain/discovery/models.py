"""Unified component model for the supply chain inventory."""

from dataclasses import dataclass, field
from datetime import datetime, timezone


@dataclass
class Component:
    ecosystem: str  # npm | pypi | ros
    name: str
    version: str
    scope: str  # direct | transitive
    origin_path: str  # manifest that declared or locked it
    origin_line: int = 0
    resolved_url: str = ""
    integrity: str = ""
    license: str = ""
    depends_on: dict[str, str] = field(default_factory=dict)  # name -> range/spec
    resolved_deps: list[str] = field(default_factory=list)  # "name@version"
    required_by: list[str] = field(default_factory=list)  # "name@version"
    repository_url: str = ""
    maintainers: list[str] = field(default_factory=list)

    @property
    def key(self) -> str:
        return f"{self.ecosystem}:{self.name}@{self.version}"

    def to_dict(self) -> dict:
        return {
            "ecosystem": self.ecosystem,
            "name": self.name,
            "version": self.version,
            "scope": self.scope,
            "key": self.key,
            "origin": {"path": self.origin_path, "line": self.origin_line},
            "resolved_url": self.resolved_url,
            "integrity": self.integrity,
            "license": self.license,
            "depends_on": self.depends_on,
            "resolved_deps": self.resolved_deps,
            "required_by": self.required_by,
            "repository_url": self.repository_url,
            "maintainers": self.maintainers,
        }


@dataclass
class Inventory:
    target: str
    components: dict[str, Component] = field(default_factory=dict)  # key -> Component
    manifests: list[dict] = field(default_factory=list)

    def add(self, component: Component) -> Component:
        existing = self.components.get(component.key)
        if existing:
            # merge: direct scope wins; union of manifest origins
            if component.scope == "direct":
                existing.scope = "direct"
            return existing
        self.components[component.key] = component
        return component

    def finalize(self) -> None:
        """Compute reverse dependencies (required_by) from resolved_deps."""
        for component in self.components.values():
            component.required_by = []
        for component in self.components.values():
            for dep_key in component.resolved_deps:
                target = self.components.get(dep_key)
                if target is not None and component.key not in target.required_by:
                    target.required_by.append(component.key)
        for component in self.components.values():
            component.required_by.sort()

    def to_dict(self) -> dict:
        components = sorted(self.components.values(), key=lambda c: (c.ecosystem, c.name, c.version))
        direct = sum(1 for c in components if c.scope == "direct")
        return {
            "generator": "trustchain-discovery",
            "target": self.target,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "manifests": self.manifests,
            "components": [c.to_dict() for c in components],
            "stats": {
                "total": len(components),
                "direct": direct,
                "transitive": len(components) - direct,
                "ecosystems": sorted({c.ecosystem for c in components}),
            },
        }
