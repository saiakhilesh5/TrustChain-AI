"""Dockerfile analysis: unpinned or :latest base images."""

import re
from pathlib import Path

FROM_RE = re.compile(r"^FROM\s+(?P<image>\S+)", re.IGNORECASE)


def scan_dockerfiles(repo_root: str) -> list[dict]:
    root = Path(repo_root)
    findings = []
    for dockerfile in sorted(root.rglob("Dockerfile*")):
        parts = set(dockerfile.relative_to(root).parts)
        if parts & {"node_modules", ".git", ".yarn", "build", "dist"}:
            continue
        rel = str(dockerfile.relative_to(root))
        for line_no, line in enumerate(dockerfile.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
            match = FROM_RE.match(line.strip())
            if not match:
                continue
            image = match["image"]
            if ":latest" in image or not _is_versioned(image):
                findings.append({
                    "type": "anomaly",
                    "anomaly": "unpinned-base-image",
                    "component": image,
                    "detail": f"Base image '{image}' is not pinned to an immutable digest or version tag — the build is not reproducible and the image content can change.",
                    "severity": "MEDIUM" if ":latest" in image else "LOW",
                    "verified": True,
                    "evidence": {
                        "kind": "dockerfile",
                        "path": rel,
                        "line": line_no,
                        "content": line.strip(),
                    },
                })
    return findings


def _is_versioned(image: str) -> bool:
    name = image.rsplit("@", 1)[0]
    if "@sha256:" in image:
        return True
    # name:tag with an explicit non-latest tag
    if ":" in name.split("/")[-1]:
        return True
    return False
