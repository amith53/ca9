from __future__ import annotations

import json

from ca9.models import Evidence, Report, Verdict, VerdictResult, Vulnerability
from ca9.report import write_json, write_sarif


def _vuln(vid: str = "CVE-2023-0001", pkg: str = "requests", sev: str = "high") -> Vulnerability:
    return Vulnerability(
        id=vid,
        package_name=pkg,
        package_version="1.0.0",
        severity=sev,
        title=f"Vulnerability in {pkg}",
        description=f"Description of {vid}",
    )


class TestSARIF:
    def test_sarif_structure(self):
        report = Report(
            results=[
                VerdictResult(
                    vulnerability=_vuln(),
                    verdict=Verdict.REACHABLE,
                    reason="imported and executed",
                    imported_as="requests",
                ),
            ],
            repo_path=".",
        )
        text = write_sarif(report)
        data = json.loads(text)

        assert data["version"] == "2.1.0"
        assert "$schema" in data
        assert len(data["runs"]) == 1

        run = data["runs"][0]
        assert run["tool"]["driver"]["name"] == "ca9"
        assert len(run["tool"]["driver"]["rules"]) == 1
        assert len(run["results"]) == 1

    def test_sarif_reachable_is_error(self):
        report = Report(
            results=[
                VerdictResult(
                    vulnerability=_vuln(),
                    verdict=Verdict.REACHABLE,
                    reason="test",
                    imported_as="requests",
                ),
            ],
            repo_path=".",
        )
        data = json.loads(write_sarif(report))
        assert data["runs"][0]["results"][0]["level"] == "error"

    def test_sarif_inconclusive_is_warning(self):
        report = Report(
            results=[
                VerdictResult(
                    vulnerability=_vuln(),
                    verdict=Verdict.INCONCLUSIVE,
                    reason="test",
                    imported_as="requests",
                ),
            ],
            repo_path=".",
        )
        data = json.loads(write_sarif(report))
        assert data["runs"][0]["results"][0]["level"] == "warning"

    def test_sarif_unreachable_is_note(self):
        report = Report(
            results=[
                VerdictResult(
                    vulnerability=_vuln(),
                    verdict=Verdict.UNREACHABLE_STATIC,
                    reason="test",
                    imported_as="requests",
                ),
            ],
            repo_path=".",
        )
        data = json.loads(write_sarif(report))
        assert data["runs"][0]["results"][0]["level"] == "note"

    def test_sarif_severity_mapping(self):
        report = Report(
            results=[
                VerdictResult(
                    vulnerability=_vuln(sev="critical"),
                    verdict=Verdict.REACHABLE,
                    reason="test",
                    imported_as="requests",
                ),
            ],
            repo_path=".",
        )
        data = json.loads(write_sarif(report))
        rule = data["runs"][0]["tool"]["driver"]["rules"][0]
        assert rule["properties"]["security-severity"] == "9.0"

    def test_sarif_deduplicates_rules(self):
        vuln = _vuln()
        report = Report(
            results=[
                VerdictResult(vulnerability=vuln, verdict=Verdict.REACHABLE, reason="r1"),
                VerdictResult(vulnerability=vuln, verdict=Verdict.REACHABLE, reason="r2"),
            ],
            repo_path=".",
        )
        data = json.loads(write_sarif(report))
        assert len(data["runs"][0]["tool"]["driver"]["rules"]) == 1
        assert len(data["runs"][0]["results"]) == 2

    def test_sarif_dependency_of(self):
        report = Report(
            results=[
                VerdictResult(
                    vulnerability=_vuln(),
                    verdict=Verdict.REACHABLE,
                    reason="test",
                    dependency_of="flask",
                ),
            ],
            repo_path=".",
        )
        data = json.loads(write_sarif(report))
        assert data["runs"][0]["results"][0]["properties"]["dependency_of"] == "flask"

    def test_sarif_write_to_file(self, tmp_path):
        report = Report(
            results=[
                VerdictResult(
                    vulnerability=_vuln(),
                    verdict=Verdict.REACHABLE,
                    reason="test",
                ),
            ],
            repo_path=".",
        )
        outfile = tmp_path / "report.sarif"
        write_sarif(report, outfile)
        data = json.loads(outfile.read_text())
        assert data["version"] == "2.1.0"

    def test_sarif_help_uri(self):
        report = Report(
            results=[
                VerdictResult(
                    vulnerability=_vuln(vid="CVE-2023-9999"),
                    verdict=Verdict.REACHABLE,
                    reason="test",
                ),
            ],
            repo_path=".",
        )
        data = json.loads(write_sarif(report))
        rule = data["runs"][0]["tool"]["driver"]["rules"][0]
        assert rule["helpUri"] == "https://osv.dev/vulnerability/CVE-2023-9999"

    def test_sarif_fingerprints(self):
        report = Report(
            results=[
                VerdictResult(
                    vulnerability=_vuln(),
                    verdict=Verdict.REACHABLE,
                    reason="test",
                    confidence_score=85,
                ),
            ],
            repo_path=".",
        )
        data = json.loads(write_sarif(report))
        result = data["runs"][0]["results"][0]
        assert "fingerprints" in result
        assert "ca9/v1" in result["fingerprints"]
        assert len(result["fingerprints"]["ca9/v1"]) == 32

    def test_sarif_confidence_in_properties(self):
        report = Report(
            results=[
                VerdictResult(
                    vulnerability=_vuln(),
                    verdict=Verdict.REACHABLE,
                    reason="test",
                    confidence_score=75,
                ),
            ],
            repo_path=".",
        )
        data = json.loads(write_sarif(report))
        props = data["runs"][0]["results"][0]["properties"]
        assert props["confidence_score"] == 75

    def test_sarif_evidence_in_properties(self):
        evidence = Evidence(
            version_in_range=True,
            package_imported=True,
            dependency_kind="direct",
            coverage_seen=True,
            coverage_files=("file1.py",),
        )
        report = Report(
            results=[
                VerdictResult(
                    vulnerability=_vuln(),
                    verdict=Verdict.REACHABLE,
                    reason="test",
                    evidence=evidence,
                ),
            ],
            repo_path=".",
        )
        data = json.loads(write_sarif(report))
        ev = data["runs"][0]["results"][0]["properties"]["evidence"]
        assert ev["version_in_range"] is True
        assert ev["package_imported"] is True
        assert ev["dependency_kind"] == "direct"

    def test_json_includes_evidence(self):
        evidence = Evidence(
            version_in_range=True,
            package_imported=True,
            dependency_kind="direct",
            affected_component_source="curated:django",
            affected_component_confidence=85,
        )
        report = Report(
            results=[
                VerdictResult(
                    vulnerability=_vuln(),
                    verdict=Verdict.REACHABLE,
                    reason="test",
                    evidence=evidence,
                    confidence_score=80,
                ),
            ],
            repo_path=".",
        )
        data = json.loads(write_json(report))
        r = data["results"][0]
        assert r["confidence_score"] == 80
        assert r["evidence"]["version_in_range"] is True
        assert r["evidence"]["affected_component_source"] == "curated:django"

    def test_sarif_fingerprint_stable(self):
        report = Report(
            results=[
                VerdictResult(
                    vulnerability=_vuln(),
                    verdict=Verdict.REACHABLE,
                    reason="test1",
                ),
                VerdictResult(
                    vulnerability=_vuln(),
                    verdict=Verdict.REACHABLE,
                    reason="test2",
                ),
            ],
            repo_path=".",
        )
        data = json.loads(write_sarif(report))
        fp1 = data["runs"][0]["results"][0]["fingerprints"]["ca9/v1"]
        fp2 = data["runs"][0]["results"][1]["fingerprints"]["ca9/v1"]
        assert fp1 == fp2
