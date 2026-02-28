"""Tests for the OSV.dev scanner."""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

from ca9.scanner import (
    _cvss_to_level,
    _extract_severity,
    _parse_cvss_score,
    get_installed_packages,
    query_osv_batch,
    scan_installed,
)


class TestGetInstalledPackages:
    def test_returns_list_of_tuples(self):
        packages = get_installed_packages()
        assert isinstance(packages, list)
        assert len(packages) > 0
        name, version = packages[0]
        assert isinstance(name, str)
        assert isinstance(version, str)

    def test_contains_known_packages(self):
        """Our dev environment has pytest and click installed."""
        packages = get_installed_packages()
        names = {name.lower() for name, _ in packages}
        assert "pytest" in names


# -- Canned data for mocking --------------------------------------------------

# Batch API returns minimal data (just IDs)
_BATCH_SINGLE = {"results": [{"vulns": [{"id": "PYSEC-2023-001"}]}]}
_BATCH_MULTIPLE = {
    "results": [
        {"vulns": [{"id": "PYSEC-2023-001"}, {"id": "PYSEC-2023-002"}]},
        {"vulns": []},
    ]
}
_BATCH_EMPTY = {"results": [{"vulns": []}]}
_BATCH_DEDUP = {
    "results": [
        {"vulns": [{"id": "PYSEC-2023-001"}]},
        {"vulns": [{"id": "PYSEC-2023-001"}]},
    ]
}

# Full vuln details (returned by individual fetch)
_VULN_DETAILS = {
    "PYSEC-2023-001": {
        "id": "PYSEC-2023-001",
        "summary": "Remote code execution in example-pkg",
        "severity": [{"type": "CVSS_V3", "score": "9.8"}],
        "database_specific": {"severity": "CRITICAL"},
    },
    "PYSEC-2023-002": {
        "id": "PYSEC-2023-002",
        "summary": "SSRF in requests",
        "database_specific": {"severity": "MEDIUM"},
    },
}


def _mock_urlopen(response_data):
    """Create a mock for urllib.request.urlopen that returns canned JSON."""
    mock_resp = MagicMock()
    mock_resp.read.return_value = json.dumps(response_data).encode()
    mock_resp.__enter__ = lambda s: s
    mock_resp.__exit__ = MagicMock(return_value=False)
    return mock_resp


class TestQueryOsvBatch:
    @patch("ca9.scanner._fetch_vuln_details")
    @patch("ca9.scanner.urllib.request.urlopen")
    def test_single_vuln(self, mock_urlopen_fn, mock_fetch):
        mock_urlopen_fn.return_value = _mock_urlopen(_BATCH_SINGLE)
        mock_fetch.side_effect = lambda vid: _VULN_DETAILS.get(vid, {})

        vulns = query_osv_batch([("example-pkg", "1.0.0")])
        assert len(vulns) == 1
        assert vulns[0].id == "PYSEC-2023-001"
        assert vulns[0].package_name == "example-pkg"
        assert vulns[0].package_version == "1.0.0"
        assert vulns[0].severity == "critical"
        assert "Remote code execution" in vulns[0].title

    @patch("ca9.scanner._fetch_vuln_details")
    @patch("ca9.scanner.urllib.request.urlopen")
    def test_multiple_vulns(self, mock_urlopen_fn, mock_fetch):
        mock_urlopen_fn.return_value = _mock_urlopen(_BATCH_MULTIPLE)
        mock_fetch.side_effect = lambda vid: _VULN_DETAILS.get(vid, {})

        vulns = query_osv_batch([("requests", "2.19.1"), ("flask", "2.0.0")])
        assert len(vulns) == 2
        assert vulns[0].id == "PYSEC-2023-001"
        assert vulns[0].severity == "critical"
        assert vulns[1].id == "PYSEC-2023-002"
        assert vulns[1].severity == "medium"

    @patch("ca9.scanner.urllib.request.urlopen")
    def test_empty_response(self, mock_urlopen_fn):
        mock_urlopen_fn.return_value = _mock_urlopen(_BATCH_EMPTY)
        vulns = query_osv_batch([("safe-pkg", "1.0.0")])
        assert vulns == []

    @patch("ca9.scanner._fetch_vuln_details")
    @patch("ca9.scanner.urllib.request.urlopen")
    def test_deduplication(self, mock_urlopen_fn, mock_fetch):
        mock_urlopen_fn.return_value = _mock_urlopen(_BATCH_DEDUP)
        mock_fetch.side_effect = lambda vid: _VULN_DETAILS.get(vid, {})

        vulns = query_osv_batch([("pkg-a", "1.0"), ("pkg-b", "2.0")])
        assert len(vulns) == 1  # Duplicate PYSEC-2023-001 is deduplicated

    def test_empty_input(self):
        vulns = query_osv_batch([])
        assert vulns == []

    @patch("ca9.scanner.urllib.request.urlopen")
    def test_network_error(self, mock_urlopen_fn):
        import urllib.error

        mock_urlopen_fn.side_effect = urllib.error.URLError("Connection refused")
        with pytest.raises(ConnectionError, match="OSV.dev API request failed"):
            query_osv_batch([("requests", "2.19.1")])

    @patch("ca9.scanner.urllib.request.urlopen")
    def test_malformed_json(self, mock_urlopen_fn):
        mock_resp = MagicMock()
        mock_resp.read.return_value = b"not json at all"
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen_fn.return_value = mock_resp
        with pytest.raises(ValueError, match="malformed JSON"):
            query_osv_batch([("requests", "2.19.1")])

    @patch("ca9.scanner._fetch_vuln_details")
    @patch("ca9.scanner.urllib.request.urlopen")
    def test_fetch_failure_graceful(self, mock_urlopen_fn, mock_fetch):
        """If individual vuln fetch fails, we still get the vuln with unknown severity."""
        mock_urlopen_fn.return_value = _mock_urlopen(_BATCH_SINGLE)
        mock_fetch.return_value = {}  # Simulate fetch failure

        vulns = query_osv_batch([("example-pkg", "1.0.0")])
        assert len(vulns) == 1
        assert vulns[0].severity == "unknown"


class TestExtractSeverity:
    def test_database_specific_first(self):
        """database_specific.severity takes priority."""
        vuln = {
            "database_specific": {"severity": "HIGH"},
            "severity": [{"type": "CVSS_V3", "score": "5.0"}],
        }
        assert _extract_severity(vuln) == "high"

    def test_cvss_v3(self):
        assert _extract_severity({"severity": [{"type": "CVSS_V3", "score": "9.8"}]}) == "critical"

    def test_cvss_v4(self):
        assert _extract_severity({"severity": [{"type": "CVSS_V4", "score": "7.5"}]}) == "high"

    def test_cvss_medium(self):
        assert _extract_severity({"severity": [{"type": "CVSS_V3", "score": "5.0"}]}) == "medium"

    def test_cvss_low(self):
        assert _extract_severity({"severity": [{"type": "CVSS_V3", "score": "2.0"}]}) == "low"

    def test_ecosystem_specific(self):
        vuln = {"affected": [{"ecosystem_specific": {"severity": "Medium"}}]}
        assert _extract_severity(vuln) == "medium"

    def test_cvss_vector_string(self):
        """CVSS vector strings should now parse correctly."""
        vuln = {
            "severity": [
                {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}
            ]
        }
        assert _extract_severity(vuln) == "critical"

    def test_unknown_fallback(self):
        assert _extract_severity({}) == "unknown"
        assert _extract_severity({"severity": []}) == "unknown"


class TestParseCvssScore:
    """CVSS vector string parsing."""

    def test_plain_numeric(self):
        assert _parse_cvss_score("9.8") == 9.8

    def test_cvss_v3_critical_vector(self):
        # CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H → 9.8
        score = _parse_cvss_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        assert score == 9.8

    def test_cvss_v3_high_vector(self):
        # CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H → 7.2
        score = _parse_cvss_score("CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H")
        assert score == 7.2

    def test_cvss_v3_medium_vector(self):
        # CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N → 4.2
        score = _parse_cvss_score("CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N")
        assert score == 4.2

    def test_cvss_v3_scope_changed(self):
        # CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H → 10.0
        score = _parse_cvss_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H")
        assert score == 10.0

    def test_cvss_v30(self):
        # Also handles CVSS:3.0 prefix
        score = _parse_cvss_score("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        assert score == 9.8

    def test_cvss_v2_returns_none(self):
        assert _parse_cvss_score("AV:N/AC:L/Au:N/C:P/I:P/A:P") is None

    def test_incomplete_vector_returns_none(self):
        assert _parse_cvss_score("CVSS:3.1/AV:N/AC:L") is None

    def test_empty_returns_none(self):
        assert _parse_cvss_score("") is None

    def test_none_returns_none(self):
        assert _parse_cvss_score(None) is None

    def test_no_impact_returns_zero(self):
        # All CIA = None → impact ≤ 0 → score = 0.0
        score = _parse_cvss_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N")
        assert score == 0.0


class TestCvssToLevel:
    def test_ranges(self):
        assert _cvss_to_level(10.0) == "critical"
        assert _cvss_to_level(9.0) == "critical"
        assert _cvss_to_level(8.0) == "high"
        assert _cvss_to_level(7.0) == "high"
        assert _cvss_to_level(5.0) == "medium"
        assert _cvss_to_level(4.0) == "medium"
        assert _cvss_to_level(1.0) == "low"
        assert _cvss_to_level(0.0) == "unknown"


class TestScanInstalled:
    @patch("ca9.scanner.query_osv_batch")
    @patch("ca9.scanner.get_installed_packages")
    def test_wires_together(self, mock_get, mock_query):
        mock_get.return_value = [("requests", "2.19.1")]
        mock_query.return_value = []
        result = scan_installed()
        mock_get.assert_called_once()
        mock_query.assert_called_once_with([("requests", "2.19.1")])
        assert result == []
