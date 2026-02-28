"""Tests for SCA report parsers."""

from __future__ import annotations

import json

from ca9.parsers import detect_parser
from ca9.parsers.dependabot import DependabotParser
from ca9.parsers.snyk import SnykParser


class TestSnykParser:
    def test_can_parse_snyk(self, snyk_path):
        data = json.loads(snyk_path.read_text())
        parser = SnykParser()
        assert parser.can_parse(data)

    def test_cannot_parse_dependabot(self, dependabot_path):
        data = json.loads(dependabot_path.read_text())
        parser = SnykParser()
        assert not parser.can_parse(data)

    def test_parse_snyk_vulns(self, snyk_path):
        data = json.loads(snyk_path.read_text())
        parser = SnykParser()
        vulns = parser.parse(data)
        assert len(vulns) == 4
        assert vulns[0].id == "SNYK-PYTHON-REQUESTS-1234567"
        assert vulns[0].package_name == "requests"
        assert vulns[0].severity == "high"

    def test_deduplicates(self):
        data = {
            "vulnerabilities": [
                {
                    "id": "V1",
                    "packageName": "foo",
                    "version": "1.0",
                    "severity": "low",
                    "title": "t",
                },
                {
                    "id": "V1",
                    "packageName": "foo",
                    "version": "1.0",
                    "severity": "low",
                    "title": "t",
                },
            ],
            "projectName": "test",
        }
        parser = SnykParser()
        vulns = parser.parse(data)
        assert len(vulns) == 1

    def test_parse_list_format(self):
        data = [
            {
                "vulnerabilities": [
                    {
                        "id": "V1",
                        "packageName": "a",
                        "version": "1",
                        "severity": "low",
                        "title": "t",
                    },
                ],
                "projectName": "p1",
            },
            {
                "vulnerabilities": [
                    {
                        "id": "V2",
                        "packageName": "b",
                        "version": "2",
                        "severity": "high",
                        "title": "t",
                    },
                ],
                "projectName": "p2",
            },
        ]
        parser = SnykParser()
        assert parser.can_parse(data)
        vulns = parser.parse(data)
        assert len(vulns) == 2


class TestDependabotParser:
    def test_can_parse_dependabot(self, dependabot_path):
        data = json.loads(dependabot_path.read_text())
        parser = DependabotParser()
        assert parser.can_parse(data)

    def test_cannot_parse_snyk(self, snyk_path):
        data = json.loads(snyk_path.read_text())
        parser = DependabotParser()
        assert not parser.can_parse(data)

    def test_parse_dependabot_vulns(self, dependabot_path):
        data = json.loads(dependabot_path.read_text())
        parser = DependabotParser()
        vulns = parser.parse(data)
        assert len(vulns) == 2
        assert vulns[0].id == "GHSA-1234-abcd-5678"
        assert vulns[0].package_name == "requests"
        assert vulns[1].severity == "critical"


class TestSnykEdgeCases:
    def test_skips_empty_ids(self):
        data = {
            "vulnerabilities": [
                {"id": "", "packageName": "foo", "version": "1.0", "severity": "low", "title": "t"},
                {
                    "id": "V1",
                    "packageName": "bar",
                    "version": "1.0",
                    "severity": "low",
                    "title": "t",
                },
            ],
            "projectName": "test",
        }
        vulns = SnykParser().parse(data)
        assert len(vulns) == 1
        assert vulns[0].id == "V1"

    def test_skips_non_dict_entries(self):
        data = [
            "not a dict",
            {
                "vulnerabilities": [
                    {
                        "id": "V1",
                        "packageName": "a",
                        "version": "1",
                        "severity": "low",
                        "title": "t",
                    }
                ],
                "projectName": "p",
            },
        ]
        vulns = SnykParser().parse(data)
        assert len(vulns) == 1

    def test_skips_non_dict_vulns(self):
        data = {
            "vulnerabilities": [
                "not a dict",
                {"id": "V1", "packageName": "a", "version": "1", "severity": "low", "title": "t"},
            ],
            "projectName": "test",
        }
        vulns = SnykParser().parse(data)
        assert len(vulns) == 1

    def test_empty_vulnerabilities_list(self):
        data = {"vulnerabilities": [], "projectName": "test"}
        vulns = SnykParser().parse(data)
        assert vulns == []


class TestDependabotEdgeCases:
    def test_skips_non_dict_alerts(self):
        data = [
            "garbage",
            {
                "number": 1,
                "security_advisory": {"ghsa_id": "GHSA-1", "summary": "t", "severity": "high"},
                "security_vulnerability": {"package": {"name": "requests"}},
            },
        ]
        vulns = DependabotParser().parse(data)
        assert len(vulns) == 1

    def test_can_parse_empty_list(self):
        assert not DependabotParser().can_parse([])

    def test_can_parse_non_list(self):
        assert not DependabotParser().can_parse({"key": "val"})


class TestAutoDetect:
    def test_detects_snyk(self, snyk_path):
        parser = detect_parser(snyk_path)
        assert isinstance(parser, SnykParser)

    def test_detects_dependabot(self, dependabot_path):
        parser = detect_parser(dependabot_path)
        assert isinstance(parser, DependabotParser)

    def test_unknown_format_raises(self, tmp_path):
        bad = tmp_path / "unknown.json"
        bad.write_text('{"random": "data"}')
        import pytest

        with pytest.raises(ValueError, match="Cannot detect SCA format"):
            detect_parser(bad)
