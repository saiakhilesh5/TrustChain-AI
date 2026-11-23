"""Repository walker: detects manifests, runs the right parser, builds the inventory."""

from pathlib import Path

from trustchain.discovery import npm, pip, ros, yarn
from trustchain.discovery.models import Inventory

SKIP_DIRS = {
    ".git", ".yarn", "node_modules", ".venv", "venv", "dist", "build",
    ".cache", "coverage", ".github/bin",
}


def discover(target: str) -> Inventory:
    root = Path(target).resolve()
    if not root.exists():
        raise FileNotFoundError(f"target does not exist: {root}")

    inventory = Inventory(target=str(root))

    package_jsons = [p for p in _walk(root) if p.name == "package.json"]
    lock = None
    for name in ("package-lock.json", "yarn.lock", "pnpm-lock.yaml"):
        found = [p for p in _walk(root) if p.name == name and p.parent == root]
        if found:
            lock = (name, found[0])
            break

    direct_names: set[str] = set()
    for pj in package_jsons:
        direct_names.update(npm.parse_package_json(pj, inventory))

    if lock:
        kind, lock_path = lock
        if kind == "package-lock.json":
            npm.parse_package_lock(lock_path, inventory, direct_names)
        elif kind == "yarn.lock":
            yarn.parse_yarn_lock(lock_path, inventory, direct_names)
        # pnpm-lock: parsed by SBOM tooling (syft) in milestone 2

    for req in (p for p in _walk(root) if p.name in ("requirements.txt", "requirements-prod.txt")):
        pip.parse_requirements(req, inventory)

    for px in (p for p in _walk(root) if p.name == "package.xml"):
        ros.parse_package_xml(px, inventory)
    ros.resolve_ros_internal(inventory)

    inventory.finalize()
    return inventory


def _walk(root: Path):
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        parts = set(path.relative_to(root).parts)
        if parts & SKIP_DIRS:
            continue
        yield path
