from __future__ import annotations

import importlib.metadata
import json
import urllib.error
import urllib.request

from ca9.models import VersionRange, Vulnerability

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns"


def get_installed_packages() -> list[tuple[str, str]]:
    packages: list[tuple[str, str]] = []
    for dist in importlib.metadata.distributions():
        name = dist.metadata["Name"]
        version = dist.metadata["Version"]
        if name and version:
            packages.append((name, version))
    return packages


def _extract_severity(osv_vuln: dict) -> str:
    db_specific = osv_vuln.get("database_specific", {})
    if isinstance(db_specific, dict):
        sev = db_specific.get("severity")
        if isinstance(sev, str) and sev.lower() in ("critical", "high", "medium", "low"):
            return sev.lower()

    for sev in osv_vuln.get("severity", []):
        score_str = sev.get("score", "")
        if sev.get("type") in ("CVSS_V3", "CVSS_V4"):
            score = _parse_cvss_score(score_str)
            if score is not None:
                return _cvss_to_level(score)

    for affected in osv_vuln.get("affected", []):
        eco = affected.get("ecosystem_specific", {})
        if isinstance(eco, dict):
            sev = eco.get("severity")
            if isinstance(sev, str) and sev.lower() in ("critical", "high", "medium", "low"):
                return sev.lower()

    return "unknown"


def _parse_cvss_score(vector: str) -> float | None:
    if not isinstance(vector, str) or not vector:
        return None

    try:
        return float(vector)
    except ValueError:
        pass

    if not vector.startswith("CVSS:3"):
        return None

    return _compute_cvss3_base_score(vector)


_CVSS3_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
_CVSS3_AC = {"L": 0.77, "H": 0.44}
_CVSS3_PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_CVSS3_PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.50}
_CVSS3_UI = {"N": 0.85, "R": 0.62}
_CVSS3_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}


def _compute_cvss3_base_score(vector: str) -> float | None:
    import math

    parts = vector.split("/")
    metrics: dict[str, str] = {}
    for part in parts[1:]:
        if ":" not in part:
            return None
        key, val = part.split(":", 1)
        metrics[key] = val

    required = {"AV", "AC", "PR", "UI", "S", "C", "I", "A"}
    if not required.issubset(metrics):
        return None

    av = _CVSS3_AV.get(metrics["AV"])
    ac = _CVSS3_AC.get(metrics["AC"])
    ui = _CVSS3_UI.get(metrics["UI"])
    scope_changed = metrics["S"] == "C"

    pr_table = _CVSS3_PR_CHANGED if scope_changed else _CVSS3_PR_UNCHANGED
    pr = pr_table.get(metrics["PR"])

    c = _CVSS3_CIA.get(metrics["C"])
    i = _CVSS3_CIA.get(metrics["I"])
    a = _CVSS3_CIA.get(metrics["A"])

    if any(v is None for v in (av, ac, pr, ui, c, i, a)):
        return None

    iss = 1.0 - ((1.0 - c) * (1.0 - i) * (1.0 - a))

    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss

    if impact <= 0:
        return 0.0

    exploitability = 8.22 * av * ac * pr * ui

    if scope_changed:
        base = min(1.08 * (impact + exploitability), 10.0)
    else:
        base = min(impact + exploitability, 10.0)

    return math.ceil(base * 10) / 10


def _cvss_to_level(score: float) -> str:
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0.0:
        return "low"
    return "unknown"


def _extract_version_ranges(osv_vuln: dict, package_name: str) -> tuple[VersionRange, ...]:
    ranges: list[VersionRange] = []
    for affected in osv_vuln.get("affected", []):
        pkg = affected.get("package", {})
        if pkg.get("ecosystem", "").lower() != "pypi":
            continue
        if pkg.get("name", "").lower() != package_name.lower():
            continue
        for r in affected.get("ranges", []):
            if r.get("type") != "ECOSYSTEM":
                continue
            introduced = ""
            fixed = ""
            last_affected = ""
            for event in r.get("events", []):
                if "introduced" in event:
                    introduced = event["introduced"]
                elif "fixed" in event:
                    fixed = event["fixed"]
                elif "last_affected" in event:
                    last_affected = event["last_affected"]
            if introduced:
                ranges.append(
                    VersionRange(
                        introduced=introduced,
                        fixed=fixed,
                        last_affected=last_affected,
                    )
                )
    return tuple(ranges)


def _extract_references(osv_vuln: dict) -> tuple[str, ...]:
    urls: list[str] = []
    for ref in osv_vuln.get("references", []):
        url = ref.get("url", "")
        if url:
            urls.append(url)
    return tuple(urls)


def _fetch_vuln_details(vuln_id: str) -> dict:
    url = f"{OSV_VULN_URL}/{vuln_id}"
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read().decode())
    except (urllib.error.URLError, urllib.error.HTTPError, OSError, json.JSONDecodeError):
        return {}


def query_osv_batch(packages: list[tuple[str, str]]) -> list[Vulnerability]:
    if not packages:
        return []

    queries = [
        {"package": {"name": name, "ecosystem": "PyPI"}, "version": version}
        for name, version in packages
    ]

    payload = json.dumps({"queries": queries}).encode()
    req = urllib.request.Request(
        OSV_BATCH_URL,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read().decode())
    except (urllib.error.URLError, urllib.error.HTTPError, OSError) as e:
        raise ConnectionError(f"OSV.dev API request failed: {e}") from e
    except json.JSONDecodeError as e:
        raise ValueError(f"OSV.dev returned malformed JSON: {e}") from e

    seen_ids: set[str] = set()
    vuln_refs: list[tuple[str, str, str]] = []

    for i, result in enumerate(data.get("results", [])):
        pkg_name = packages[i][0] if i < len(packages) else "unknown"
        pkg_version = packages[i][1] if i < len(packages) else "unknown"

        for osv_vuln in result.get("vulns", []):
            vuln_id = osv_vuln.get("id", "")
            if not vuln_id or vuln_id in seen_ids:
                continue
            seen_ids.add(vuln_id)
            vuln_refs.append((vuln_id, pkg_name, pkg_version))

    vulns: list[Vulnerability] = []
    for vuln_id, pkg_name, pkg_version in vuln_refs:
        details = _fetch_vuln_details(vuln_id)
        severity = _extract_severity(details) if details else "unknown"
        title = (
            details.get("summary", "") or details.get("details", "No description")[:120]
            if details
            else vuln_id
        )

        description = details.get("details", "") if details else ""

        affected_ranges = _extract_version_ranges(details, pkg_name) if details else ()
        references = _extract_references(details) if details else ()

        vulns.append(
            Vulnerability(
                id=vuln_id,
                package_name=pkg_name,
                package_version=pkg_version,
                severity=severity,
                title=title,
                description=description,
                affected_ranges=affected_ranges,
                references=references,
            )
        )

    return vulns


def scan_installed() -> list[Vulnerability]:
    packages = get_installed_packages()
    return query_osv_batch(packages)
