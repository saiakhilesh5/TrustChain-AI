"""Append-only evidence ledger: single source of truth for all findings."""

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path


@dataclass
class EvidenceStore:
    run_id: str
    target: str = ""
    entries: list[dict] = field(default_factory=list)

    def ingest(self, findings: list[dict], source: str) -> None:
        for finding in findings:
            entry = dict(finding)
            entry_id = f"T-{len(self.entries) + 1:04d}"
            entry["id"] = entry_id
            entry["source"] = source
            entry.setdefault("verified", True)
            entry.setdefault("inference", None)
            self.entries.append(entry)

    @property
    def verified(self) -> list[dict]:
        return [e for e in self.entries if e.get("verified")]

    @property
    def inferred(self) -> list[dict]:
        return [e for e in self.entries if not e.get("verified")]

    def to_dict(self) -> dict:
        return {
            "run_id": self.run_id,
            "target": self.target,
            "recorded_at": datetime.now(timezone.utc).isoformat(),
            "entries": self.entries,
            "stats": {
                "total": len(self.entries),
                "verified": len(self.verified),
                "inferred": len(self.inferred),
            },
        }

    def save(self, path: Path) -> None:
        path.write_text(json.dumps(self.to_dict(), indent=2), encoding="utf-8")

    @classmethod
    def load(cls, path: Path) -> "EvidenceStore":
        data = json.loads(path.read_text(encoding="utf-8"))
        store = cls(run_id=data["run_id"], target=data.get("target", ""))
        store.entries = data["entries"]
        return store
