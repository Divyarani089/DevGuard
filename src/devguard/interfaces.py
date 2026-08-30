"""Scanner contract for DevGuard modules."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Sequence

from .models import Finding


class BaseScanner(ABC):
    """Base interface for all scanner implementations."""

    name: str = "base"

    @abstractmethod
    def scan(self, project_path: str) -> Sequence[Finding]:
        """Scan a project and return standardized findings."""
        raise NotImplementedError
