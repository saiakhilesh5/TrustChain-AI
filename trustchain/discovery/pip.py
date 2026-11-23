"""pip ecosystem parser: requirements.txt files (direct, pinned dependencies)."""

import re
from pathlib import Path

from trustchain.discovery.models import Component, Inventory

_SPEC = re.compile(r"^(?P<name>[A-Za-z0-9._-]+)(?P<extras>\[[^\]]*\])?\s*(?P<op>[=<>~!]=?|===)?\s*(?P<version>[^\s,;#]+)?")
# PEP 508-ish names; extras and markers after ';' are ignored
_NORMALIZE = re.compile(r"[-_.]+")


def parse_requirements(path: Path, inventory: Inventory) -> None:
    rel = str(path)
    inventory.manifests.append({"type": "pip-requirements", "path": rel})
    for line_no, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith("-") or line.startswith("git+"):
            continue
        match = _SPEC.match(line)
        if match is None:
            continue
        name = _NORMALIZE.sub("-", match["name"]).lower()
        op = match["op"] or ""
        version = match["version"] or ""
        if op not in ("==", "==="):
            # unpinned or ranged requirement: record with empty version
            version = ""
        inventory.add(
            Component(
                ecosystem="pypi",
                name=name,
                version=version or "unknown",
                scope="direct",
                origin_path=rel,
                origin_line=line_no,
                depends_on={} if not version else {name: f"{op}{version}"},
            )
        )
