"""OSV.dev vulnerability correlation with disk caching and batch queries."""

import time
from pathlib import Path

import requests

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns/{vuln_id}"
OSV_ECOSYSTEM = {"npm": "npm", "pypi": "PyPI"}

BATCH_SIZE = 500
REQUEST_DELAY = 0.05


class OsvClient:
    def __init__(self, cache_dir: Path | None = None, session: requests.Session | None = None):
        self.session = session or requests.Session()
        self.cache_dir = cache_dir
        self._queries: dict[str, list[str]] = {}  # "eco:name@version" -> vuln ids
        self._vulns: dict[str, dict] = {}
        if cache_dir is not None:
            cache_dir.mkdir(parents=True, exist_ok=True)
            self._load_cache()

    def _load_cache(self) -> None:
        q_file = self.cache_dir / "osv_query_cache.json"
        v_file = self.cache_dir / "osv_vuln_cache.json"
        if q_file.exists():
            self._queries = _read_json(q_file)
        if v_file.exists():
            self._vulns = _read_json(v_file)

    def _save_cache(self) -> None:
        if self.cache_dir is None:
            return
        _write_json(self.cache_dir / "osv_query_cache.json", self._queries)
        _write_json(self.cache_dir / "osv_vuln_cache.json", self._vulns)

    def query_vuln_ids(self, ecosystem: str, name: str, version: str) -> list[str]:
        if ecosystem not in OSV_ECOSYSTEM:
            return []
        cache_key = f"{ecosystem}:{name}@{version}"
        if cache_key in self._queries:
            return self._queries[cache_key]

        eco = OSV_ECOSYSTEM[ecosystem]
        response = self.session.post(OSV_BATCH_URL, json={
            "queries": [{"package": {"name": name, "ecosystem": eco}, "version": version}],
        }, timeout=30)
        response.raise_for_status()
        ids = [v["id"] for v in response.json()["results"][0].get("vulns", [])]
        time.sleep(REQUEST_DELAY)
        self._queries[cache_key] = ids
        self._save_cache()
        return ids

    def query_batch(self, components: list[dict]) -> dict[str, list[str]]:
        """Batch query: components are inventory dicts. Returns key -> vuln ids."""
        pending: list[tuple[str, dict]] = []
        results: dict[str, list[str]] = {}
        for comp in components:
            eco = comp["ecosystem"]
            if eco not in OSV_ECOSYSTEM or comp["version"] == "unknown":
                continue
            cache_key = f"{eco}:{comp['name']}@{comp['version']}"
            if cache_key in self._queries:
                results[comp["key"]] = self._queries[cache_key]
            else:
                pending.append((cache_key, comp))

        queries_payload = []
        keys_in_flight: list[str] = []
        component_keys: list[str] = []
        for cache_key, comp in pending:
            queries_payload.append({
                "package": {"name": comp["name"], "ecosystem": OSV_ECOSYSTEM[comp["ecosystem"]]},
                "version": comp["version"],
            })
            keys_in_flight.append(cache_key)
            component_keys.append(comp["key"])
            if len(queries_payload) == BATCH_SIZE:
                self._flush_batch(queries_payload, keys_in_flight, component_keys, results)
                queries_payload, keys_in_flight, component_keys = [], [], []
        if queries_payload:
            self._flush_batch(queries_payload, keys_in_flight, component_keys, results)
        return results

    def _flush_batch(self, queries, cache_keys, component_keys, results) -> None:
        response = self.session.post(OSV_BATCH_URL, json={"queries": queries}, timeout=60)
        response.raise_for_status()
        batch_results = response.json()["results"]
        for cache_key, component_key, result in zip(cache_keys, component_keys, batch_results):
            ids = [v["id"] for v in result.get("vulns", [])]
            self._queries[cache_key] = ids
            results[component_key] = ids
        self._save_cache()
        time.sleep(REQUEST_DELAY)

    def get_vuln(self, vuln_id: str) -> dict:
        if vuln_id in self._vulns:
            return self._vulns[vuln_id]
        response = self.session.get(OSV_VULN_URL.format(vuln_id=vuln_id), timeout=30)
        response.raise_for_status()
        data = response.json()
        self._vulns[vuln_id] = data
        self._save_cache()
        time.sleep(REQUEST_DELAY)
        return data


def _read_json(path: Path) -> dict:
    import json
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}


def _write_json(path: Path, data: dict) -> None:
    import json
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")
