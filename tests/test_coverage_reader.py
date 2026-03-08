from __future__ import annotations

from ca9.analysis.coverage_reader import (
    are_call_sites_covered,
    get_coverage_completeness,
    get_covered_files,
    is_package_executed,
    is_submodule_executed,
    load_coverage,
)


class TestGetCoveredFiles:
    def test_extracts_files_with_lines(self, coverage_path):
        data = load_coverage(coverage_path)
        files = get_covered_files(data)
        assert len(files) == 3
        assert any("requests/api.py" in f for f in files)

    def test_excludes_empty_executed_lines(self, coverage_path):
        data = load_coverage(coverage_path)
        files = get_covered_files(data)
        yaml_files = [f for f in files if "yaml" in f]
        assert len(yaml_files) == 0


class TestGetCoverageCompleteness:
    def test_get_coverage_completeness_with_totals(self):
        data = {"totals": {"percent_covered": 85.3}}
        assert get_coverage_completeness(data) == 85.3

    def test_get_coverage_completeness_no_totals(self):
        data = {"files": {}, "meta": {}}
        assert get_coverage_completeness(data) is None

    def test_get_coverage_completeness_empty_data(self):
        assert get_coverage_completeness({}) is None


class TestIsPackageExecuted:
    def test_requests_executed(self, coverage_path):
        data = load_coverage(coverage_path)
        files = get_covered_files(data)
        executed, matching = is_package_executed("requests", files)
        assert executed
        assert len(matching) == 2

    def test_yaml_not_executed(self, coverage_path):
        data = load_coverage(coverage_path)
        files = get_covered_files(data)
        executed, matching = is_package_executed("PyYAML", files)
        assert not executed

    def test_unknown_package(self, coverage_path):
        data = load_coverage(coverage_path)
        files = get_covered_files(data)
        executed, matching = is_package_executed("nonexistent-pkg", files)
        assert not executed
        assert matching == []


class TestEdgeCases:
    def test_missing_files_key(self):
        files = get_covered_files({"meta": {}})
        assert files == {}

    def test_empty_coverage_data(self):
        files = get_covered_files({})
        assert files == {}

    def test_windows_paths(self):
        covered = {
            "C:\\Python39\\Lib\\site-packages\\requests\\api.py": [1, 2, 3],
        }
        executed, matching = is_package_executed("requests", covered)
        assert executed
        assert len(matching) == 1


class TestIsSubmoduleExecuted:
    def test_submodule_as_directory(self):
        covered = {
            "/site-packages/jinja2/sandbox/__init__.py": [1, 2],
            "/site-packages/jinja2/utils.py": [1],
        }
        executed, matching = is_submodule_executed(("jinja2.sandbox",), (), covered)
        assert executed
        assert len(matching) == 1
        assert "sandbox" in matching[0]

    def test_submodule_as_file(self):
        covered = {
            "/site-packages/jinja2/sandbox.py": [1, 2, 3],
        }
        executed, matching = is_submodule_executed(("jinja2.sandbox",), (), covered)
        assert executed

    def test_submodule_not_executed(self):
        covered = {
            "/site-packages/jinja2/utils.py": [1, 2],
            "/site-packages/jinja2/filters.py": [1],
        }
        executed, matching = is_submodule_executed(("jinja2.sandbox",), (), covered)
        assert not executed
        assert matching == []

    def test_file_hints(self):
        covered = {
            "/site-packages/werkzeug/debugger.py": [1, 2],
        }
        executed, matching = is_submodule_executed((), ("debugger.py",), covered)
        assert executed

    def test_multiple_submodule_paths(self):
        covered = {
            "/site-packages/django/contrib/admin/sites.py": [1],
            "/site-packages/django/db/models/query.py": [5],
        }
        executed, matching = is_submodule_executed(("django.contrib.admin",), (), covered)
        assert executed
        assert len(matching) == 1

    def test_empty_paths_and_hints(self):
        covered = {"/site-packages/jinja2/sandbox.py": [1]}
        executed, matching = is_submodule_executed((), (), covered)
        assert not executed

    def test_windows_paths(self):
        covered = {
            "C:\\Python39\\Lib\\site-packages\\werkzeug\\debug\\__init__.py": [1],
        }
        executed, matching = is_submodule_executed(("werkzeug.debug",), (), covered)
        assert executed


class TestAreCallSitesCovered:
    def test_call_site_covered(self):
        covered = {
            "/repo/app.py": [1, 5, 10, 15, 20],
            "/repo/utils.py": [1, 2, 3],
        }
        result, cov_count, total = are_call_sites_covered(
            [("/repo/app.py", 10)], covered
        )
        assert result is True
        assert cov_count == 1
        assert total == 1

    def test_call_site_not_covered(self):
        covered = {
            "/repo/app.py": [1, 5, 10, 15, 20],
        }
        result, cov_count, total = are_call_sites_covered(
            [("/repo/app.py", 42)], covered
        )
        assert result is False
        assert cov_count == 0
        assert total == 1

    def test_mixed_covered_and_uncovered(self):
        covered = {
            "/repo/app.py": [1, 5, 10],
            "/repo/views.py": [1, 2, 3],
        }
        result, cov_count, total = are_call_sites_covered(
            [("/repo/app.py", 5), ("/repo/views.py", 99)], covered
        )
        assert result is True
        assert cov_count == 1
        assert total == 2

    def test_no_call_sites(self):
        covered = {"/repo/app.py": [1, 2]}
        result, cov_count, total = are_call_sites_covered([], covered)
        assert result is None
        assert cov_count == 0
        assert total == 0

    def test_call_site_file_not_in_coverage(self):
        covered = {"/repo/app.py": [1, 2, 3]}
        result, cov_count, total = are_call_sites_covered(
            [("/repo/other.py", 1)], covered
        )
        assert result is None
        assert total == 0

    def test_suffix_path_matching(self):
        covered = {
            "/full/path/to/repo/app.py": [1, 5, 10],
        }
        result, cov_count, total = are_call_sites_covered(
            [("repo/app.py", 5)], covered
        )
        assert result is True
        assert cov_count == 1

    def test_multiple_call_sites_all_covered(self):
        covered = {
            "/repo/app.py": [1, 5, 10, 20],
        }
        result, cov_count, total = are_call_sites_covered(
            [("/repo/app.py", 5), ("/repo/app.py", 10)], covered
        )
        assert result is True
        assert cov_count == 2
        assert total == 2

    def test_windows_path_normalization(self):
        covered = {
            "C:\\repo\\app.py": [1, 5, 10],
        }
        result, cov_count, total = are_call_sites_covered(
            [("C:/repo/app.py", 5)], covered
        )
        assert result is True
