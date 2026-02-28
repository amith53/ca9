"""Tests for version-range filtering."""

from __future__ import annotations

from ca9.models import VersionRange
from ca9.version import is_version_affected


class TestIsVersionAffected:
    def test_within_range(self):
        ranges = (VersionRange(introduced="1.0", fixed="1.5"),)
        assert is_version_affected("1.3", ranges) is True

    def test_at_introduced(self):
        ranges = (VersionRange(introduced="1.0", fixed="1.5"),)
        assert is_version_affected("1.0", ranges) is True

    def test_at_fixed(self):
        ranges = (VersionRange(introduced="1.0", fixed="1.5"),)
        assert is_version_affected("1.5", ranges) is False

    def test_after_fixed(self):
        ranges = (VersionRange(introduced="1.0", fixed="1.5"),)
        assert is_version_affected("2.0", ranges) is False

    def test_before_introduced(self):
        ranges = (VersionRange(introduced="1.0", fixed="1.5"),)
        assert is_version_affected("0.9", ranges) is False

    def test_multiple_ranges(self):
        ranges = (
            VersionRange(introduced="1.0", fixed="1.5"),
            VersionRange(introduced="2.0", fixed="2.3"),
        )
        assert is_version_affected("1.2", ranges) is True
        assert is_version_affected("1.7", ranges) is False
        assert is_version_affected("2.1", ranges) is True
        assert is_version_affected("2.5", ranges) is False

    def test_last_affected(self):
        ranges = (VersionRange(introduced="1.0", last_affected="1.5"),)
        assert is_version_affected("1.5", ranges) is True
        assert is_version_affected("1.6", ranges) is False

    def test_no_upper_bound(self):
        """Range with introduced but no fixed/last_affected — all versions after introduced."""
        ranges = (VersionRange(introduced="1.0"),)
        assert is_version_affected("1.0", ranges) is True
        assert is_version_affected("99.0", ranges) is True
        assert is_version_affected("0.5", ranges) is False

    def test_empty_ranges(self):
        assert is_version_affected("1.0", ()) is None

    def test_no_introduced(self):
        """Range without introduced is not usable."""
        ranges = (VersionRange(fixed="1.5"),)
        assert is_version_affected("1.0", ranges) is None

    def test_three_part_versions(self):
        ranges = (VersionRange(introduced="2.1.0", fixed="2.1.2"),)
        assert is_version_affected("2.1.1", ranges) is True
        assert is_version_affected("2.1.2", ranges) is False
        assert is_version_affected("2.0.9", ranges) is False

    def test_zero_introduced(self):
        """introduced=0 means all versions before fixed."""
        ranges = (VersionRange(introduced="0", fixed="1.5"),)
        assert is_version_affected("0.1", ranges) is True
        assert is_version_affected("1.5", ranges) is False
