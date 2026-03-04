from __future__ import annotations

import json

from click.testing import CliRunner

from ca9.cli import main


class TestCLI:
    def test_table_output(self, snyk_path, sample_repo):
        runner = CliRunner()
        result = runner.invoke(main, [str(snyk_path), "--repo", str(sample_repo)])
        assert result.exit_code in (0, 1, 2)
        assert "requests" in result.output
        assert "UNREACHABLE" in result.output or "INCONCLUSIVE" in result.output

    def test_json_output(self, snyk_path, sample_repo):
        runner = CliRunner()
        result = runner.invoke(
            main, [str(snyk_path), "--repo", str(sample_repo), "-f", "json", "--no-auto-coverage"]
        )
        assert result.exit_code in (0, 1, 2)
        raw = result.output.strip()
        json_start = raw.index("{")
        json_end = raw.rindex("}") + 1
        data = json.loads(raw[json_start:json_end])
        assert "results" in data
        assert "summary" in data
        assert data["summary"]["total"] == 4

    def test_with_coverage(self, snyk_path, sample_repo, coverage_path):
        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                str(snyk_path),
                "--repo",
                str(sample_repo),
                "--coverage",
                str(coverage_path),
                "-f",
                "json",
            ],
        )
        data = json.loads(result.output)
        verdicts = {r["package"]: r["verdict"] for r in data["results"]}
        assert verdicts["requests"] == "reachable"
        assert verdicts["some-unused-package"] == "unreachable_static"
        assert result.exit_code == 1

    def test_output_to_file(self, snyk_path, sample_repo, tmp_path):
        output_file = tmp_path / "report.json"
        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                str(snyk_path),
                "--repo",
                str(sample_repo),
                "-f",
                "json",
                "-o",
                str(output_file),
            ],
        )
        assert result.exit_code in (0, 1, 2)
        assert output_file.exists()
        data = json.loads(output_file.read_text())
        assert data["summary"]["total"] == 4

    def test_no_vulns(self, tmp_path, sample_repo):
        empty = tmp_path / "empty.json"
        empty.write_text('{"vulnerabilities": [], "projectName": "x"}')
        runner = CliRunner()
        result = runner.invoke(main, [str(empty), "--repo", str(sample_repo)])
        assert result.exit_code == 0
        assert "No vulnerabilities" in result.output

    def test_invalid_json(self, tmp_path, sample_repo):
        bad = tmp_path / "bad.json"
        bad.write_text("not valid json {{{")
        runner = CliRunner()
        result = runner.invoke(main, [str(bad), "--repo", str(sample_repo)])
        assert result.exit_code != 0
        assert "Invalid JSON" in result.output

    def test_unknown_format(self, tmp_path, sample_repo):
        unknown = tmp_path / "unknown.json"
        unknown.write_text('{"random": "data"}')
        runner = CliRunner()
        result = runner.invoke(main, [str(unknown), "--repo", str(sample_repo)])
        assert result.exit_code != 0
        assert "Cannot detect SCA format" in result.output

    def test_output_creates_parent_dir(self, snyk_path, sample_repo, tmp_path):
        output_file = tmp_path / "subdir" / "deep" / "report.json"
        runner = CliRunner()
        runner.invoke(
            main,
            [
                str(snyk_path),
                "--repo",
                str(sample_repo),
                "-f",
                "json",
                "-o",
                str(output_file),
            ],
        )
        assert output_file.exists()

    def test_sarif_output(self, snyk_path, sample_repo):
        runner = CliRunner()
        result = runner.invoke(
            main, [str(snyk_path), "--repo", str(sample_repo), "-f", "sarif", "--no-auto-coverage"]
        )
        raw = result.output.strip()
        json_start = raw.index("{")
        json_end = raw.rindex("}") + 1
        data = json.loads(raw[json_start:json_end])
        assert data["version"] == "2.1.0"
        assert len(data["runs"][0]["results"]) == 4

    def test_exit_code_with_reachable(self, snyk_path, sample_repo, coverage_path):
        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                str(snyk_path),
                "--repo",
                str(sample_repo),
                "--coverage",
                str(coverage_path),
                "-f",
                "json",
            ],
        )
        data = json.loads(result.output)
        has_reachable = any(r["verdict"] == "reachable" for r in data["results"])
        if has_reachable:
            assert result.exit_code == 1

    def test_exit_code_no_vulns(self, tmp_path, sample_repo):
        empty = tmp_path / "empty.json"
        empty.write_text('{"vulnerabilities": [], "projectName": "x"}')
        runner = CliRunner()
        result = runner.invoke(main, [str(empty), "--repo", str(sample_repo)])
        assert result.exit_code == 0
