from __future__ import annotations

import enum
from dataclasses import dataclass, field


@dataclass(frozen=True)
class AffectedComponent:
    package_import_name: str
    submodule_paths: tuple[str, ...] = ()
    file_hints: tuple[str, ...] = ()
    confidence: str = "low"
    extraction_source: str = ""


class Verdict(enum.Enum):
    REACHABLE = "reachable"
    UNREACHABLE_STATIC = "unreachable_static"
    UNREACHABLE_DYNAMIC = "unreachable_dynamic"
    INCONCLUSIVE = "inconclusive"


@dataclass(frozen=True)
class VersionRange:
    introduced: str = ""
    fixed: str = ""
    last_affected: str = ""


@dataclass(frozen=True)
class Vulnerability:
    id: str
    package_name: str
    package_version: str
    severity: str
    title: str
    description: str = ""
    affected_ranges: tuple[VersionRange, ...] = ()
    references: tuple[str, ...] = ()


@dataclass
class VerdictResult:
    vulnerability: Vulnerability
    verdict: Verdict
    reason: str
    imported_as: str | None = None
    executed_files: list[str] = field(default_factory=list)
    dependency_of: str | None = None
    affected_component: AffectedComponent | None = None


@dataclass
class Report:
    results: list[VerdictResult]
    repo_path: str
    coverage_path: str | None = None

    @property
    def total(self) -> int:
        return len(self.results)

    @property
    def reachable_count(self) -> int:
        return sum(1 for r in self.results if r.verdict == Verdict.REACHABLE)

    @property
    def unreachable_count(self) -> int:
        return sum(
            1
            for r in self.results
            if r.verdict in (Verdict.UNREACHABLE_STATIC, Verdict.UNREACHABLE_DYNAMIC)
        )

    @property
    def inconclusive_count(self) -> int:
        return sum(1 for r in self.results if r.verdict == Verdict.INCONCLUSIVE)
