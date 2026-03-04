from __future__ import annotations

from pathlib import Path


def find_config(start: Path | None = None) -> Path | None:
    current = (start or Path.cwd()).resolve()
    for directory in (current, *current.parents):
        candidate = directory / ".ca9.toml"
        if candidate.is_file():
            return candidate
    return None


def load_config(path: Path) -> dict:
    try:
        import tomllib
    except ModuleNotFoundError:
        return {}

    with open(path, "rb") as f:
        return tomllib.load(f)
