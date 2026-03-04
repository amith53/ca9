from __future__ import annotations

from typing import Any

from ca9.models import Vulnerability, finding_key


class SnykParser:
    def can_parse(self, data: Any) -> bool:
        if isinstance(data, list):
            data = data[0] if data else {}
        return (
            isinstance(data, dict)
            and "vulnerabilities" in data
            and ("projectName" in data or "packageManager" in data)
        )

    def parse(self, data: Any) -> list[Vulnerability]:
        entries = data if isinstance(data, list) else [data]

        vulns: list[Vulnerability] = []
        seen: set[tuple[str, str, str]] = set()

        for entry in entries:
            if not isinstance(entry, dict):
                continue
            for v in entry.get("vulnerabilities", []):
                if not isinstance(v, dict):
                    continue
                vuln_id = v.get("id", "")
                if not vuln_id:
                    continue
                pkg_name = v.get("packageName", v.get("moduleName", ""))
                pkg_version = v.get("version", "")
                key = finding_key(vuln_id, pkg_name, pkg_version)
                if key in seen:
                    continue
                seen.add(key)

                vulns.append(
                    Vulnerability(
                        id=vuln_id,
                        package_name=pkg_name,
                        package_version=pkg_version,
                        severity=v.get("severity", "unknown"),
                        title=v.get("title", ""),
                        description=v.get("description", ""),
                    )
                )

        return vulns
