from __future__ import annotations

import json
from pathlib import Path

from ca9.analysis.ast_scanner import pypi_to_import_name


def load_coverage(coverage_path: Path) -> dict:
    return json.loads(coverage_path.read_text())


def get_covered_files(coverage_data: dict) -> dict[str, list[int]]:
    files: dict[str, list[int]] = {}
    file_data = coverage_data.get("files", {})
    for filepath, info in file_data.items():
        executed = info.get("executed_lines", [])
        if executed:
            files[filepath] = executed
    return files


def is_package_executed(
    package_name: str,
    covered_files: dict[str, list[int]],
) -> tuple[bool, list[str]]:
    import_name = pypi_to_import_name(package_name)
    path_fragment = import_name.replace(".", "/")

    matching_files: list[str] = []

    for filepath in covered_files:
        normalized = filepath.replace("\\", "/").lower()
        if (
            f"site-packages/{path_fragment}/" in normalized
            or f"site-packages/{path_fragment}.py" in normalized
            or normalized.endswith(f"/{path_fragment}/__init__.py")
            or normalized.endswith(f"/{path_fragment}.py")
        ):
            matching_files.append(filepath)

    return bool(matching_files), matching_files


def is_submodule_executed(
    submodule_paths: tuple[str, ...],
    file_hints: tuple[str, ...],
    covered_files: dict[str, list[int]],
) -> tuple[bool, list[str]]:
    matching_files: list[str] = []

    fragments: list[str] = []
    for submod in submodule_paths:
        fragment = submod.replace(".", "/")
        fragments.append(fragment)

    for filepath in covered_files:
        normalized = filepath.replace("\\", "/").lower()

        for fragment in fragments:
            if (
                f"/{fragment}/" in normalized
                or f"/{fragment}.py" in normalized
                or normalized.endswith(f"/{fragment}/__init__.py")
                or normalized.endswith(f"/{fragment}.py")
            ):
                matching_files.append(filepath)
                break
        else:
            for hint in file_hints:
                if normalized.endswith(f"/{hint.lower()}"):
                    matching_files.append(filepath)
                    break

    return bool(matching_files), matching_files
