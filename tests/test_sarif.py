"""Tests for SARIF output format."""

from __future__ import annotations

import json

from ca9.models import Report, Verdict, VerdictResult, Vulnerability
from ca9.report import write_sarif


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
