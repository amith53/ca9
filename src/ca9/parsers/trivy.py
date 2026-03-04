from __future__ import annotations

from typing import Any

from ca9.models import Vulnerability, finding_key


class TrivyParser:
    def can_parse(self, data: Any) -> bool:
        if not isinstance(data, dict):
            return False
        return "Results" in data or (
            "SchemaVersion" in data and "results" in {k.lower() for k in data}
        )

    def parse(self, data: Any) -> list[Vulnerability]:
        vulns: list[Vulnerability] = []
        seen: set[tuple[str, str, str]] = set()

        for result in data.get("Results", []):
            if not isinstance(result, dict):
                continue
            for v in result.get("Vulnerabilities", []):
                if not isinstance(v, dict):
                    continue
                vuln_id = v.get("VulnerabilityID", "")
                if not vuln_id:
                    continue
                pkg_name = v.get("PkgName", "")
                pkg_version = v.get("InstalledVersion", "")
                key = finding_key(vuln_id, pkg_name, pkg_version)
                if key in seen:
                    continue
                seen.add(key)

                vulns.append(
                    Vulnerability(
                        id=vuln_id,
                        package_name=pkg_name,
                        package_version=pkg_version,
                        severity=v.get("Severity", "unknown").lower(),
                        title=v.get("Title", ""),
                        description=v.get("Description", ""),
                    )
                )

        return vulns
