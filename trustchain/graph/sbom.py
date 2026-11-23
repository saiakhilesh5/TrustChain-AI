"""CycloneDX 1.5 SBOM generation from the component inventory."""

import uuid
from datetime import datetime, timezone
from urllib.parse import quote

from trustchain import __version__

PURL_PREFIX = {"npm": "npm", "pypi": "pypi", "ros": "ros"}


def _purl(ecosystem: str, name: str, version: str) -> str:
    prefix = PURL_PREFIX.get(ecosystem, "generic")
    encoded_name = name.replace("@", "%40") if ecosystem == "npm" else quote(name)
    return f"pkg:{prefix}/{encoded_name}@{version}"


def _component_ref(component: dict) -> str:
    return _purl(component["ecosystem"], component["name"], component["version"])


def generate_cyclonedx(inventory: dict, root_name: str | None = None) -> dict:
    """Generate a CycloneDX 1.5 JSON document from an inventory dict (to_dict output)."""
    components = inventory["components"]
    root_ref = "root"
    key_to_ref = {c["key"]: _component_ref(c) for c in components}
    all_keys = set(key_to_ref)

    bom_components = []
    for comp in components:
        entry = {
            "bom-ref": _component_ref(comp),
            "type": "library",
            "name": comp.get("name", ""),
            "version": comp.get("version", ""),
            "purl": _component_ref(comp),
            "scope": "required" if comp.get("scope", "") == "direct" else "optional",
        }
        if comp.get("integrity", ""):
            algo = "SHA-512" if comp.get("integrity", "").startswith("sha512") else "SHA-256"
            entry["hashes"] = [{"alg": algo, "content": comp.get("integrity", "").split("-", 1)[-1]}]
        if comp.get("license", ""):
            entry["licenses"] = [{"license": {"name": comp.get("license", "")}}]
        if comp.get("repository_url", ""):
            entry["externalReferences"] = [{"type": "vcs", "url": comp.get("repository_url", "")}]
        bom_components.append(entry)

    dependencies = [
        {"ref": root_ref, "dependsOn": [_component_ref(c) for c in components if c["scope"] == "direct"]},
    ]
    for comp in components:
        dependencies.append({
            "ref": _component_ref(comp),
            "dependsOn": [key_to_ref[dep] for dep in comp.get("resolved_deps", []) if dep in all_keys],
        })

    root_name = root_name or inventory.get("target", "application").rstrip("/\\").split("/")[-1]
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tools": [{"vendor": "TrustChain-AI", "name": "trustchain", "version": __version__}],
            "component": {
                "bom-ref": root_ref,
                "type": "application",
                "name": root_name,
                "version": "unknown",
            },
        },
        "components": bom_components,
        "dependencies": dependencies,
    }
