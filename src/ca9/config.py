from __future__ import annotations

from pathlib import Path


def find_config(start: Path | None = None) -> Path | None:
    """Search for .ca9.toml from start directory upward."""
    current = (start or Path.cwd()).resolve()
    for directory in (current, *current.parents):
        candidate = directory / ".ca9.toml"
        if candidate.is_file():
            return candidate
    return None


def load_config(path: Path) -> dict:
    """Load and return config dict from a TOML file."""
    try:
        import tomllib
    except ModuleNotFoundError:
        # Python 3.10 — skip config
        return {}

    with open(path, "rb") as f:
        return tomllib.load(f)
