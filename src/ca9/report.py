from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path
from typing import TextIO

from ca9.models import Report, Verdict

_VERDICT_LABELS = {
    Verdict.REACHABLE: "REACHABLE",
    Verdict.UNREACHABLE_STATIC: "UNREACHABLE (static)",
    Verdict.UNREACHABLE_DYNAMIC: "UNREACHABLE (dynamic)",
    Verdict.INCONCLUSIVE: "INCONCLUSIVE",
}

_SARIF_LEVELS = {
    Verdict.REACHABLE: "error",
    Verdict.INCONCLUSIVE: "warning",
    Verdict.UNREACHABLE_STATIC: "note",
    Verdict.UNREACHABLE_DYNAMIC: "note",
}

_SEVERITY_RANKS = {
    "critical": "9.0",
    "high": "7.0",
    "medium": "4.0",
    "low": "1.0",
    "unknown": "0.0",
}


def _evidence_to_dict(evidence) -> dict | None:
    if evidence is None:
        return None
    d = {
        "version_in_range": evidence.version_in_range,
        "dependency_kind": evidence.dependency_kind,
        "package_imported": evidence.package_imported,
        "submodule_imported": evidence.submodule_imported,
        "affected_component_source": evidence.affected_component_source,
        "affected_component_confidence": evidence.affected_component_confidence,
        "coverage_seen": evidence.coverage_seen,
        "coverage_files": list(evidence.coverage_files),
        "external_fetch_warnings": list(evidence.external_fetch_warnings),
    }
    if evidence.api_targets:
        d["api_targets"] = list(evidence.api_targets)
    if evidence.api_usage_seen is not None:
        d["api_usage_seen"] = evidence.api_usage_seen
    if evidence.api_usage_confidence is not None:
        d["api_usage_confidence"] = evidence.api_usage_confidence
    if evidence.api_usage_hits:
        d["api_usage_hits"] = [
            {
                "file": h.file_path,
                "line": h.line,
                "target": h.matched_target,
                "type": h.match_type,
                "snippet": h.code_snippet,
            }
            for h in evidence.api_usage_hits
        ]
    if evidence.intel_rule_ids:
        d["intel_rule_ids"] = list(evidence.intel_rule_ids)
    return d


def report_to_dict(report: Report) -> dict:
    return {
        "repo_path": report.repo_path,
        "coverage_path": report.coverage_path,
        "summary": {
            "total": report.total,
            "reachable": report.reachable_count,
            "unreachable": report.unreachable_count,
            "inconclusive": report.inconclusive_count,
        },
        "results": [
            {
                "id": r.vulnerability.id,
                "package": r.vulnerability.package_name,
                "version": r.vulnerability.package_version,
                "severity": r.vulnerability.severity,
                "title": r.vulnerability.title,
                "verdict": r.verdict.value,
                "reason": r.reason,
                "imported_as": r.imported_as,
                "dependency_of": r.dependency_of,
                "executed_files": r.executed_files,
                "confidence_score": r.confidence_score,
                "affected_component": (
                    {
                        "submodule_paths": list(r.affected_component.submodule_paths),
                        "confidence": r.affected_component.confidence,
                        "extraction_source": r.affected_component.extraction_source,
                    }
                    if r.affected_component
                    else None
                ),
                "evidence": _evidence_to_dict(r.evidence),
            }
            for r in report.results
        ],
    }


def write_json(report: Report, output: Path | TextIO | None = None) -> str:
    data = report_to_dict(report)
    text = json.dumps(data, indent=2)

    if isinstance(output, Path):
        output.write_text(text)
    elif output is not None:
        output.write(text)

    return text


def write_table(
    report: Report,
    output: TextIO | None = None,
    verbose: bool = False,
    show_confidence: bool = False,
    show_evidence_source: bool = False,
) -> str:
    if output is None:
        output = sys.stdout

    if report.results:
        id_w = max(len("CVE ID"), *(len(r.vulnerability.id) for r in report.results))
    else:
        id_w = len("CVE ID")
    if report.results:
        pkg_w = max(len("Package"), *(len(r.vulnerability.package_name) for r in report.results))
    else:
        pkg_w = len("Package")
    if report.results:
        sev_w = max(len("Severity"), *(len(r.vulnerability.severity) for r in report.results))
    else:
        sev_w = len("Severity")
    if report.results:
        ver_w = max(len("Verdict"), *(len(_VERDICT_LABELS[r.verdict]) for r in report.results))
    else:
        ver_w = len("Verdict")

    header_parts = [
        f"{'CVE ID':<{id_w}}",
        f"{'Package':<{pkg_w}}",
        f"{'Severity':<{sev_w}}",
        f"{'Verdict':<{ver_w}}",
    ]
    if show_confidence:
        header_parts.append(f"{'Conf':>4}")
    if show_evidence_source:
        header_parts.append(f"{'Source':<20}")

    header = "  ".join(header_parts)
    sep = "-" * len(header)

    lines = [
        "",
        header,
        sep,
    ]

    seen_vuln_pkg: set[tuple[str, str]] = set()

    for r in report.results:
        label = _VERDICT_LABELS[r.verdict]
        group_key = (r.vulnerability.id, r.vulnerability.package_name.lower())
        is_repeat = group_key in seen_vuln_pkg
        seen_vuln_pkg.add(group_key)

        if is_repeat:
            row_parts = [
                f"{'  +' + r.vulnerability.package_version:<{id_w}}",
                f"{'\"':<{pkg_w}}",
                f"{'\"':<{sev_w}}",
                f"{'\"':<{ver_w}}",
            ]
            if show_confidence:
                row_parts.append(f"{r.confidence_score:>4}")
            if show_evidence_source:
                row_parts.append(f"{'':<20}")
            row = "  ".join(row_parts)
            lines.append(row)
        else:
            row_parts = [
                f"{r.vulnerability.id:<{id_w}}",
                f"{r.vulnerability.package_name:<{pkg_w}}",
                f"{r.vulnerability.severity:<{sev_w}}",
                f"{label:<{ver_w}}",
            ]
            if show_confidence:
                row_parts.append(f"{r.confidence_score:>4}")
            if show_evidence_source:
                source = ""
                if r.evidence:
                    source = r.evidence.affected_component_source[:20]
                row_parts.append(f"{source:<20}")

            row = "  ".join(row_parts)
            lines.append(row)
            if verbose:
                lines.append(f"  {'':>{id_w}} -> {r.reason}")

    lines.append(sep)
    lines.append(
        f"Total: {report.total}  |  "
        f"Reachable: {report.reachable_count}  |  "
        f"Unreachable: {report.unreachable_count}  |  "
        f"Inconclusive: {report.inconclusive_count}"
    )

    if report.total > 0 and report.unreachable_count > 0:
        pct = round(report.unreachable_count / report.total * 100)
        actionable = report.reachable_count + report.inconclusive_count
        lines.append("")
        lines.append(
            f"{pct}% of flagged CVEs are unreachable "
            f"— only {actionable} of {report.total} require action"
        )

    lines.append("")

    text = "\n".join(lines)
    output.write(text)
    return text


def _stable_fingerprint(vuln_id: str, package: str, version: str, verdict: str) -> str:
    data = f"{vuln_id}|{package}|{version}|{verdict}"
    return hashlib.sha256(data.encode()).hexdigest()[:32]


def write_sarif(report: Report, output: Path | TextIO | None = None) -> str:
    rules = []
    results = []
    seen_rule_ids: set[str] = set()

    for r in report.results:
        vuln = r.vulnerability
        rule_id = vuln.id

        if rule_id not in seen_rule_ids:
            seen_rule_ids.add(rule_id)
            rule = {
                "id": rule_id,
                "shortDescription": {"text": vuln.title or rule_id},
                "helpUri": f"https://osv.dev/vulnerability/{rule_id}",
                "properties": {
                    "security-severity": _SEVERITY_RANKS.get(vuln.severity.lower(), "0.0"),
                    "tags": ["security", "vulnerability"],
                },
            }
            if vuln.description:
                rule["fullDescription"] = {"text": vuln.description}
            rules.append(rule)

        message_parts = [
            f"{vuln.package_name}@{vuln.package_version}: {vuln.title}",
            f"Verdict: {_VERDICT_LABELS[r.verdict]}",
            f"Reason: {r.reason}",
        ]

        fingerprint = _stable_fingerprint(
            vuln.id, vuln.package_name, vuln.package_version, r.verdict.value
        )

        result = {
            "ruleId": rule_id,
            "level": _SARIF_LEVELS[r.verdict],
            "message": {"text": "\n".join(message_parts)},
            "fingerprints": {
                "ca9/v1": fingerprint,
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": r.imported_as or vuln.package_name,
                            "uriBaseId": "%SRCROOT%",
                        },
                    },
                },
            ],
            "properties": {
                "verdict": r.verdict.value,
                "package": vuln.package_name,
                "version": vuln.package_version,
                "severity": vuln.severity,
                "confidence_score": r.confidence_score,
            },
        }

        if r.evidence:
            result["properties"]["evidence"] = _evidence_to_dict(r.evidence)

        if r.dependency_of:
            result["properties"]["dependency_of"] = r.dependency_of
        results.append(result)

    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "ca9",
                        "informationUri": "https://github.com/oha/ca9",
                        "version": "0.1.2",
                        "rules": rules,
                    },
                },
                "results": results,
            },
        ],
    }

    text = json.dumps(sarif, indent=2)

    if isinstance(output, Path):
        output.write_text(text)
    elif output is not None:
        output.write(text)

    return text
