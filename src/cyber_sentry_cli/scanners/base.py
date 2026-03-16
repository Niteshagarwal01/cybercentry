# pyre-unsafe
"""Base scanner interface — all scanner adapters inherit from this."""

from __future__ import annotations

import shutil
import sys
from abc import ABC, abstractmethod
from pathlib import Path

from cyber_sentry_cli.core.models import Finding


def find_tool(name: str) -> str | None:
    """Find a tool on PATH or in the current venv's Scripts/bin directory."""
    found = shutil.which(name)
    if found:
        return found
    # Look in the same directory as the running Python executable (venv Scripts/bin)
    scripts_dir = Path(sys.executable).parent
    for candidate in [name, name + ".exe"]:
        full = scripts_dir / candidate
        if full.exists():
            return str(full)
    return None


class BaseScanner(ABC):
    """Abstract scanner interface."""

    name: str = "base"

    @abstractmethod
    def scan(self, target: Path) -> list[Finding]:
        """Scan the target and return normalized findings."""
        ...

    @abstractmethod
    def is_available(self) -> bool:
        """Check if this scanner is installed and accessible."""
        ...
