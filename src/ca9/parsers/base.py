from __future__ import annotations

from typing import Any, Protocol

from ca9.models import Vulnerability


class SCAParser(Protocol):
    def can_parse(self, data: Any) -> bool: ...

    def parse(self, data: Any) -> list[Vulnerability]: ...
