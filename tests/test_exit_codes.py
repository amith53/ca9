"""Tests for exit code differentiation."""

from __future__ import annotations

from ca9.models import Report, Verdict, VerdictResult, Vulnerability


def _vuln(vid: str = "V1") -> Vulnerability:
    return Vulnerability(
        id=vid,
        package_name="pkg",
        package_version="1.0",
        severity="high",
        title="test",
    )


def _result(verdict: Verdict) -> VerdictResult:
    return VerdictResult(
        vulnerability=_vuln(),
        verdict=verdict,
        reason="test",
    )


class TestExitCodes:
    def test_clean_report_exit_0(self):
        report = Report(
            results=[_result(Verdict.UNREACHABLE_STATIC)],
            repo_path=".",
        )
        assert report.exit_code == 0

    def test_empty_report_exit_0(self):
        report = Report(results=[], repo_path=".")
        assert report.exit_code == 0

    def test_reachable_exit_1(self):
        report = Report(
            results=[
                _result(Verdict.REACHABLE),
                _result(Verdict.UNREACHABLE_STATIC),
            ],
            repo_path=".",
        )
        assert report.exit_code == 1

    def test_inconclusive_only_exit_2(self):
        report = Report(
            results=[
                _result(Verdict.INCONCLUSIVE),
                _result(Verdict.UNREACHABLE_STATIC),
            ],
            repo_path=".",
        )
        assert report.exit_code == 2

    def test_reachable_beats_inconclusive(self):
        report = Report(
            results=[
                _result(Verdict.REACHABLE),
                _result(Verdict.INCONCLUSIVE),
            ],
            repo_path=".",
        )
        assert report.exit_code == 1

    def test_all_unreachable_dynamic_exit_0(self):
        report = Report(
            results=[_result(Verdict.UNREACHABLE_DYNAMIC)],
            repo_path=".",
        )
        assert report.exit_code == 0

    def test_mixed_unreachable_exit_0(self):
        report = Report(
            results=[
                _result(Verdict.UNREACHABLE_STATIC),
                _result(Verdict.UNREACHABLE_DYNAMIC),
            ],
            repo_path=".",
        )
        assert report.exit_code == 0
