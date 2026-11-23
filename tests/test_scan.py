import pytest

from trustchain.scan import correlate


class FakeClient:
    """Deterministic stand-in for the OSV API."""

    def __init__(self, cache_dir=None):
        self.cache_dir = cache_dir

    def query_batch(self, components):
        results = {}
        for comp in components:
            if comp["name"] == "lodash" and comp["version"] == "4.17.20":
                results[comp["key"]] = ["GHSA-34dd-mhg5-9h7f"]
            elif comp["name"] == "chalk" and comp["version"] == "4.0.0":
                results[comp["key"]] = ["GHSA-fake-chalk"]
        return results

    def get_vuln(self, vuln_id):
        advisories = {
            "GHSA-34dd-mhg5-9h7f": {
                "id": "GHSA-34dd-mhg5-9h7f",
                "aliases": ["CVE-2020-8203"],
                "summary": "Prototype pollution in lodash",
                "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
                "affected": [
                    {"package": {"name": "lodash", "ecosystem": "npm"},
                     "ranges": [{"events": [{"fixed": "4.17.21"}, {"fixed": "4.17.19"}]}]}
                ],
                "references": [{"url": "https://osv.dev/vulnerability/GHSA-34dd-mhg5-9h7f"}],
            },
            "GHSA-fake-chalk": {
                "id": "GHSA-fake-chalk",
                "summary": "no severity data",
                "database_specific": {"severity": "MODERATE"},
                "affected": [],
            },
        }
        return advisories[vuln_id]


INVENTORY = {
    "target": "app",
    "components": [
        {"key": "npm:chalk@5.0.0", "ecosystem": "npm", "name": "chalk", "version": "5.0.0",
         "scope": "direct", "resolved_deps": ["npm:lodash@4.17.20"]},
        {"key": "npm:lodash@4.17.20", "ecosystem": "npm", "name": "lodash", "version": "4.17.20",
         "scope": "transitive", "resolved_deps": []},
    ],
}


def test_scan_vulnerabilities(monkeypatch):
    monkeypatch.setattr(correlate, "OsvClient", FakeClient)
    findings = correlate.scan_vulnerabilities(INVENTORY)
    assert len(findings) == 1
    finding = findings[0]
    assert finding["cve"] == "CVE-2020-8203"
    assert finding["severity"] == "CRITICAL"
    assert "4.17.21" in finding["fixed_versions"]
    assert finding["dependency_paths"] == [["chalk@5.0.0", "lodash@4.17.20"]]
    assert finding["verified"] is True


def test_cvss_vector_scores():
    # canonical vectors, scores verified against the FIRST v3.1 formula
    assert correlate._cvss_score_from_vector(
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") == 9.8
    assert correlate._cvss_score_from_vector(
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H") == 10
    assert correlate._cvss_score_from_vector(
        "CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N") == 2.6
    assert correlate._cvss_score_from_vector(
        "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N") == 1.8


def test_severity_fallback_from_database_specific(monkeypatch):
    monkeypatch.setattr(correlate, "OsvClient", FakeClient)
    inventory = {
        "target": "app",
        "components": [
            {"key": "npm:chalk@4.0.0", "ecosystem": "npm", "name": "chalk", "version": "4.0.0",
             "scope": "direct", "resolved_deps": []},
        ],
    }
    findings = correlate.scan_vulnerabilities(inventory)
    assert findings[0]["severity"] == "MODERATE"
