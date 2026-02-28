from __future__ import annotations

from typing import Any

from ca9.models import Vulnerability


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
        seen_ids: set[str] = set()

        for entry in entries:
            if not isinstance(entry, dict):
                continue
            for v in entry.get("vulnerabilities", []):
                if not isinstance(v, dict):
                    continue
                vuln_id = v.get("id", "")
                if not vuln_id:
                    continue
                if vuln_id in seen_ids:
                    continue
                seen_ids.add(vuln_id)

                vulns.append(
                    Vulnerability(
                        id=vuln_id,
                        package_name=v.get("packageName", v.get("moduleName", "")),
                        package_version=v.get("version", ""),
                        severity=v.get("severity", "unknown"),
                        title=v.get("title", ""),
                        description=v.get("description", ""),
                    )
                )

        return vulns
