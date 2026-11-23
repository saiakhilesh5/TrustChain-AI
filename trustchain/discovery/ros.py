"""ROS ecosystem parser: package.xml manifests (format 2 and 3)."""

import xml.etree.ElementTree as ET
from pathlib import Path

from trustchain.discovery.models import Component, Inventory

DEPEND_TAGS = (
    "build_depend",
    "build_export_depend",
    "buildtool_depend",
    "buildtool_export_depend",
    "exec_depend",
    "run_depend",
    "test_depend",
    "doc_depend",
)


def parse_package_xml(path: Path, inventory: Inventory) -> None:
    rel = str(path)
    root = ET.parse(path).getroot()
    inventory.manifests.append({"type": "ros-package", "path": rel})

    def text(tag: str) -> str:
        node = root.find(tag)
        return (node.text or "").strip() if node is not None else ""

    maintainers = []
    for node in root.findall("maintainer"):
        maintainers.append(node.text or node.get("email", ""))

    repository_url = ""
    for url_node in root.findall("url"):
        if url_node.get("type") == "repository":
            repository_url = (url_node.text or "").strip()

    component = Component(
        ecosystem="ros",
        name=text("name") or path.parent.name,
        version=text("version") or "unknown",
        scope="direct",
        origin_path=rel,
        license=text("license"),
        repository_url=repository_url,
        maintainers=maintainers,
    )
    inventory.add(component)

    for tag in DEPEND_TAGS:
        for dep in root.findall(tag):
            dep_name = (dep.text or "").strip()
            if dep_name:
                component.depends_on.setdefault(dep_name, tag)


def resolve_ros_internal(inventory: Inventory) -> None:
    """ROS deps are unversioned names; link to other packages in the same repo
    (already registered). External deps remain depends_on without a resolved edge."""
    ros_components = [c for c in inventory.components.values() if c.ecosystem == "ros"]
    by_name: dict[str, list[Component]] = {}
    for comp in ros_components:
        by_name.setdefault(comp.name, []).append(comp)
    for comp in ros_components:
        for dep_name in comp.depends_on:
            for target in by_name.get(dep_name, []):
                if target.key != comp.key and target.key not in comp.resolved_deps:
                    comp.resolved_deps.append(target.key)
