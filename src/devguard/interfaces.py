"""Plugin interface for security scanners."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Sequence

from .models import Finding


class BaseScanner(ABC):
    """Base contract for all DevGuard scanner implementations.

    Future scanner modules from Samarth or Krushnarth can subclass this contract and
    return a list of standardized Finding objects.
    """

    name: str = "base"

    @abstractmethod
    def scan(self, project_path: str) -> Sequence[Finding]:
        """Inspect a project directory and return findings."""
        raise NotImplementedError
