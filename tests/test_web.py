import json

from trustchain.web.checklist import build_checklist
from trustchain.web.graph_json import build_graph_payload
from trustchain.web.runner import RunManager


def _write_run(tmp_path):
    run_dir = tmp_path / "outputs" / "run1"
    run_dir.mkdir(parents=True)
    (run_dir / "inventory.json").write_text(json.dumps({
        "target": "app", "stats": {"total": 3, "direct": 1, "transitive": 2},
        "components": [
            {"key": "npm:a@1", "name": "a", "version": "1", "scope": "direct",
             "ecosystem": "npm", "depends_on": [], "resolved_deps": ["npm:b@2"]},
            {"key": "npm:b@2", "name": "b", "version": "2", "scope": "transitive",
             "ecosystem": "npm", "depends_on": ["npm:a@1"], "resolved_deps": []},
        ],
    }), encoding="utf-8")
    (run_dir / "sbom.cdx.json").write_text(json.dumps({"components": [{}, {}]}), encoding="utf-8")
    (run_dir / "vulnerabilities.json").write_text(json.dumps([
        {"severity": "HIGH", "component": "npm:b@2", "dependency_paths": [["ROOT", "npm:a@1", "npm:b@2"]]},
    ]), encoding="utf-8")
    (run_dir / "anomalies.json").write_text(json.dumps([
        {"anomaly": "unpinned-action", "severity": "MEDIUM", "component": "ci"},
    ]), encoding="utf-8")
    return run_dir


def test_checklist_from_artifacts(tmp_path):
    run_dir = _write_run(tmp_path)
    steps = [
        {"id": sid, "status": "done"} for sid in
        ["clone", "discover", "sbom", "vulns", "anomalies", "graph", "report"]
    ]
    data = build_checklist(run_dir, steps)
    by_id = {item["id"]: item for item in data["items"]}
    assert by_id["discover"]["status"] == "done"
    assert "3 components" in by_id["discover"]["detail"]
    assert by_id["vulns"]["status"] == "done"
    assert "1 findings, 1 with dependency paths" in by_id["vulns"]["detail"]
    assert data["completed"] == 5  # graph.json and evidence report missing
    assert data["percent"] == 71


def test_graph_payload_highlights_vulnerable():
    from trustchain.graph.depgraph import build_graph

    inventory = {"components": [
        {"key": "npm:a@1", "name": "a", "version": "1", "scope": "direct",
         "ecosystem": "npm", "resolved_deps": ["npm:b@2"]},
        {"key": "npm:b@2", "name": "b", "version": "2", "scope": "transitive",
         "ecosystem": "npm", "resolved_deps": []},
    ]}
    graph = build_graph(inventory)
    payload = build_graph_payload(graph, {"npm:b@2"})
    groups = {n["id"]: n["group"] for n in payload["nodes"]}
    assert groups["ROOT"] == "root"
    assert groups["npm:a@1"] == "direct"
    assert groups["npm:b@2"] == "vulnerable"
    assert payload["stats"]["vulnerable"] == 1
    assert len(payload["edges"]) == 2


def test_url_validation():
    for bad in ["", "ftp://example.com/x", "https://gitlab.com/a/b", "javascript:alert(1)"]:
        try:
            RunManager.normalize_url(bad)
            raised = False
        except Exception:
            raised = True
        assert raised, bad
    assert RunManager.normalize_url("https://github.com/strapi/strapi.git/") == \
        "https://github.com/strapi/strapi"


def test_api_endpoints(tmp_path):
    from trustchain.web.app import create_app

    _write_run(tmp_path)
    app = create_app(base_dir=tmp_path)
    client = app.test_client()

    assert client.get("/api/health").status_code == 200

    response = client.post("/api/scan", json={"url": "https://gitlab.com/a/b"})
    assert response.status_code == 400
    assert "github.com" in response.get_json()["error"]

    response = client.post("/api/scan", json={})
    assert response.status_code == 400

    runs = client.get("/api/runs").get_json()
    assert runs[0]["id"] == "run1"
    assert runs[0]["status"] == "done"

    response = client.get("/api/runs/run1/checklist")
    assert response.status_code == 200
    checklist = response.get_json()
    assert checklist["total"] == 7

    response = client.get("/api/runs/run1/inventory")
    assert response.get_json()["stats"]["total"] == 3

    response = client.get("/api/runs/run1/vulnerabilities")
    assert response.get_json()["total"] == 1

    response = client.get("/api/runs/run1/anomalies")
    assert response.get_json()["total"] == 1

    response = client.get("/api/runs/run1/graph")
    assert response.status_code == 404  # not built in this fixture

    response = client.get("/api/runs/nope/checklist")
    assert response.status_code == 404

    response = client.get("/api/runs/run1/artifacts/../inventory.json")
    assert response.status_code in (400, 404)  # path traversal rejected
