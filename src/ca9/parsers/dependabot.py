from __future__ import annotations

from typing import Any

from ca9.models import Vulnerability


class DependabotParser:
    def can_parse(self, data: Any) -> bool:
        if not isinstance(data, list) or not data:
            return False
        first = data[0]
        return isinstance(first, dict) and (
            "security_advisory" in first or "security_vulnerability" in first
        )

    def parse(self, data: Any) -> list[Vulnerability]:
        vulns: list[Vulnerability] = []
        seen_ids: set[str] = set()

        for alert in data:
            if not isinstance(alert, dict):
                continue
            advisory = alert.get("security_advisory", {})
            sec_vuln = alert.get("security_vulnerability", {})
            dep = alert.get("dependency", {})

            pkg = sec_vuln.get("package", dep.get("package", {}))
            vuln_id = advisory.get(
                "ghsa_id", advisory.get("cve_id", f"ALERT-{alert.get('number', '?')}")
            )

            if vuln_id in seen_ids:
                continue
            seen_ids.add(vuln_id)

            vulns.append(
                Vulnerability(
                    id=vuln_id,
                    package_name=pkg.get("name", ""),
                    package_version=sec_vuln.get("vulnerable_version_range", ""),
                    severity=advisory.get("severity", "unknown"),
                    title=advisory.get("summary", ""),
                    description=advisory.get("description", ""),
                )
            )

        return vulns
