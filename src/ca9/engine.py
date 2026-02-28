from __future__ import annotations

from pathlib import Path

from ca9.analysis.ast_scanner import (
    collect_imports_from_repo,
    is_package_imported,
    is_submodule_imported,
    pypi_to_import_name,
    resolve_transitive_deps,
)
from ca9.analysis.coverage_reader import (
    get_covered_files,
    is_package_executed,
    is_submodule_executed,
    load_coverage,
)
from ca9.analysis.vuln_matcher import extract_affected_component
from ca9.models import Report, Verdict, VerdictResult, Vulnerability
from ca9.version import is_version_affected


def analyze(
    vulnerabilities: list[Vulnerability],
    repo_path: Path,
    coverage_path: Path | None = None,
) -> Report:
    repo_imports = collect_imports_from_repo(repo_path)
    transitive_deps = resolve_transitive_deps(repo_imports)

    covered_files: dict[str, list[int]] | None = None
    if coverage_path:
        coverage_data = load_coverage(coverage_path)
        covered_files = get_covered_files(coverage_data)

    results: list[VerdictResult] = []

    for vuln in vulnerabilities:
        import_name = pypi_to_import_name(vuln.package_name)

        if vuln.affected_ranges:
            affected = is_version_affected(vuln.package_version, vuln.affected_ranges)
            if affected is False:
                results.append(
                    VerdictResult(
                        vulnerability=vuln,
                        verdict=Verdict.UNREACHABLE_STATIC,
                        reason=(
                            f"'{vuln.package_name}' {vuln.package_version} is outside "
                            f"the affected version range"
                        ),
                        imported_as=import_name,
                    )
                )
                continue

        direct = is_package_imported(vuln.package_name, repo_imports)
        dep_of = transitive_deps.get(vuln.package_name.lower()) if not direct else None
        imported = direct or dep_of is not None

        component = extract_affected_component(vuln)

        if not imported:
            results.append(
                VerdictResult(
                    vulnerability=vuln,
                    verdict=Verdict.UNREACHABLE_STATIC,
                    reason=f"'{vuln.package_name}' is not imported and not a dependency of any imported package",
                    imported_as=import_name,
                    affected_component=component,
                )
            )
            continue

        if direct:
            trace = f"'{import_name}' is directly imported"
        else:
            trace = f"'{vuln.package_name}' is a dependency of {dep_of}"

        has_submodule_info = component.submodule_paths and component.confidence in (
            "high",
            "medium",
        )

        if has_submodule_info:
            sub_imported, _matched_import = is_submodule_imported(
                component.submodule_paths,
                repo_imports,
            )
            if not sub_imported:
                bare_import = not any(
                    imp.lower().startswith(import_name.lower() + ".") for imp in repo_imports
                )
                if not bare_import:
                    submod_list = ", ".join(component.submodule_paths)
                    results.append(
                        VerdictResult(
                            vulnerability=vuln,
                            verdict=Verdict.UNREACHABLE_STATIC,
                            reason=f"{trace}, but affected submodule {submod_list} is not imported",
                            imported_as=import_name,
                            dependency_of=dep_of,
                            affected_component=component,
                        )
                    )
                    continue

            if covered_files is None:
                results.append(
                    VerdictResult(
                        vulnerability=vuln,
                        verdict=Verdict.INCONCLUSIVE,
                        reason=f"{trace}, but no coverage data to confirm execution",
                        imported_as=import_name,
                        dependency_of=dep_of,
                        affected_component=component,
                    )
                )
                continue

            executed, matching_files = is_submodule_executed(
                component.submodule_paths,
                component.file_hints,
                covered_files,
            )

            if not executed:
                submod_list = ", ".join(component.submodule_paths)
                results.append(
                    VerdictResult(
                        vulnerability=vuln,
                        verdict=Verdict.UNREACHABLE_DYNAMIC,
                        reason=f"{trace}, {submod_list} imported but 0 files executed in tests",
                        imported_as=import_name,
                        dependency_of=dep_of,
                        affected_component=component,
                    )
                )
            else:
                results.append(
                    VerdictResult(
                        vulnerability=vuln,
                        verdict=Verdict.REACHABLE,
                        reason=f"{trace} and submodule code was executed in {len(matching_files)} file(s)",
                        imported_as=import_name,
                        executed_files=matching_files,
                        dependency_of=dep_of,
                        affected_component=component,
                    )
                )
            continue

        if covered_files is None:
            results.append(
                VerdictResult(
                    vulnerability=vuln,
                    verdict=Verdict.INCONCLUSIVE,
                    reason=f"{trace}, but no coverage data to confirm execution",
                    imported_as=import_name,
                    dependency_of=dep_of,
                    affected_component=component,
                )
            )
            continue

        executed, matching_files = is_package_executed(vuln.package_name, covered_files)

        if not executed:
            results.append(
                VerdictResult(
                    vulnerability=vuln,
                    verdict=Verdict.UNREACHABLE_DYNAMIC,
                    reason=f"{trace}, but no code was executed in tests",
                    imported_as=import_name,
                    dependency_of=dep_of,
                    affected_component=component,
                )
            )
        else:
            results.append(
                VerdictResult(
                    vulnerability=vuln,
                    verdict=Verdict.REACHABLE,
                    reason=f"{trace} and code was executed in {len(matching_files)} file(s)",
                    imported_as=import_name,
                    executed_files=matching_files,
                    dependency_of=dep_of,
                    affected_component=component,
                )
            )

    return Report(
        results=results,
        repo_path=str(repo_path),
        coverage_path=str(coverage_path) if coverage_path else None,
    )
