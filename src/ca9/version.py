from __future__ import annotations

from ca9.models import VersionRange


def _parse_version(v: str) -> tuple[int, ...]:
    parts: list[int] = []
    for segment in v.split("."):
        numeric = ""
        for ch in segment:
            if ch.isdigit():
                numeric += ch
            else:
                break
        if numeric:
            parts.append(int(numeric))
        else:
            parts.append(0)
    return tuple(parts)


def _version_lt(a: str, b: str) -> bool:
    return _parse_version(a) < _parse_version(b)


def _version_ge(a: str, b: str) -> bool:
    return _parse_version(a) >= _parse_version(b)


def is_version_affected(version: str, ranges: tuple[VersionRange, ...]) -> bool | None:
    if not ranges:
        return None

    has_usable_range = False

    for r in ranges:
        if not r.introduced:
            continue
        has_usable_range = True

        if _version_lt(version, r.introduced):
            continue

        if r.fixed and _version_ge(version, r.fixed):
            continue

        if (
            r.last_affected
            and not _version_lt(version, r.last_affected)
            and version != r.last_affected
        ):
            if _parse_version(version) > _parse_version(r.last_affected):
                continue

        return True

    if not has_usable_range:
        return None

    return False
