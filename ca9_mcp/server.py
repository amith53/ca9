from __future__ import annotations

import json
import os
from pathlib import Path

from mcp.server.fastmcp import FastMCP

mcp = FastMCP(
    "ca9",
    instructions="CVE reachability analysis for Python projects",
)


@mcp.tool()
def check_reachability(
    report_path: str,
    repo_path: str = ".",
    coverage_path: str | None = None,
    format: str = "json",
) -> str:

    from ca9.coverage_provider import resolve_coverage
    from ca9.engine import analyze
    from ca9.parsers import detect_parser
    from ca9.report import report_to_dict, write_table

    report_file = Path(report_path)
    if not report_file.is_file():
        return json.dumps({"error": f"Report file not found: {report_path}"})

    repo = Path(repo_path)

    cov_path = Path(coverage_path) if coverage_path else None
    cov_path = resolve_coverage(cov_path, repo, auto_generate=False)

    try:
        parser = detect_parser(report_file)
    except ValueError as e:
        return json.dumps({"error": str(e)})

    data = json.loads(report_file.read_text())
    vulnerabilities = parser.parse(data)

    if not vulnerabilities:
        return json.dumps({"results": [], "summary": {"total": 0}})

    report = analyze(vulnerabilities, repo, cov_path)

    if format == "table":
        import io

        buf = io.StringIO()
        write_table(report, buf, verbose=True, show_confidence=True)
        return buf.getvalue()

    return json.dumps(report_to_dict(report), indent=2)


@mcp.tool()
def scan_dependencies(
    repo_path: str = ".",
    coverage_path: str | None = None,
) -> str:

    from ca9.coverage_provider import resolve_coverage
    from ca9.engine import analyze
    from ca9.report import report_to_dict
    from ca9.scanner import get_installed_packages, query_osv_batch

    repo = Path(repo_path)

    cov_path = Path(coverage_path) if coverage_path else None
    cov_path = resolve_coverage(cov_path, repo, auto_generate=False)

    packages = get_installed_packages()
    vulnerabilities = query_osv_batch(packages)

    if not vulnerabilities:
        return json.dumps({
            "message": "No known vulnerabilities found in installed packages.",
            "packages_scanned": len(packages),
        })

    report = analyze(vulnerabilities, repo, cov_path)
    result = report_to_dict(report)
    result["packages_scanned"] = len(packages)
    return json.dumps(result, indent=2)


@mcp.tool()
def check_coverage_quality(
    coverage_path: str | None = None,
    repo_path: str = ".",
) -> str:

    from ca9.analysis.coverage_reader import (
        get_coverage_completeness,
        get_covered_files,
        load_coverage,
    )
    from ca9.coverage_provider import resolve_coverage

    repo = Path(repo_path)
    cov_path = Path(coverage_path) if coverage_path else None
    cov_path = resolve_coverage(cov_path, repo, auto_generate=False)

    if cov_path is None or not cov_path.is_file():
        return json.dumps({
            "error": "No coverage data found. Run pytest with pytest-cov or provide a coverage.json path.",
        })

    coverage_data = load_coverage(cov_path)
    pct = get_coverage_completeness(coverage_data)
    covered_files = get_covered_files(coverage_data)

    if pct is None:
        trust_tier = "unknown"
        recommendation = "Coverage file lacks totals — cannot assess quality."
    elif pct >= 80:
        trust_tier = "high"
        recommendation = "Dynamic absence signals are highly reliable."
    elif pct >= 50:
        trust_tier = "moderate"
        recommendation = "Dynamic absence signals are moderately reliable. Increase coverage for better results."
    elif pct >= 30:
        trust_tier = "low"
        recommendation = "Coverage is sparse. Dynamic absence signals have limited reliability."
    else:
        trust_tier = "very_low"
        recommendation = "Coverage is very sparse. Dynamic absence signals are almost meaningless."

    return json.dumps({
        "coverage_path": str(cov_path),
        "percent_covered": pct,
        "trust_tier": trust_tier,
        "files_with_execution": len(covered_files),
        "recommendation": recommendation,
    }, indent=2)


@mcp.tool()
def explain_verdict(
    vuln_id: str,
    package_name: str,
    repo_path: str = ".",
) -> str:

    from ca9.coverage_provider import resolve_coverage
    from ca9.engine import analyze
    from ca9.report import report_to_dict
    from ca9.scanner import get_installed_packages, query_osv_batch

    repo = Path(repo_path)
    cov_path = resolve_coverage(None, repo, auto_generate=False)

    packages = get_installed_packages()
    vulnerabilities = query_osv_batch(packages)

    matching = [
        v for v in vulnerabilities
        if v.id == vuln_id or v.package_name.lower() == package_name.lower()
    ]

    if not matching:
        return json.dumps({
            "error": f"No vulnerability found matching id='{vuln_id}' and package='{package_name}'.",
            "hint": "Run scan_dependencies first to see all known vulnerabilities.",
        })

    report = analyze(matching, repo, cov_path)
    data = report_to_dict(report)

    for result in data.get("results", []):
        if result["id"] == vuln_id:
            return json.dumps(result, indent=2)

    if data.get("results"):
        return json.dumps(data["results"][0], indent=2)

    return json.dumps({"error": "Analysis produced no results for the given vulnerability."})


def main():
    transport = os.environ.get("MCP_TRANSPORT", "stdio")
    if transport == "sse":
        mcp.run(transport="sse")
    else:
        mcp.run(transport="stdio")
