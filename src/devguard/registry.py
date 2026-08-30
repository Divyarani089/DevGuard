"""Scanner registry for DevGuard."""

from __future__ import annotations

from typing import Iterable

from .file_risk import FileRiskScanner
from .interfaces import BaseScanner
from .secret_detector import SecretScanner

_REGISTERED_SCANNERS: list[BaseScanner] = []


def register_scanner(scanner: BaseScanner) -> BaseScanner:
    """Register a scanner implementation."""
    if scanner not in _REGISTERED_SCANNERS:
        _REGISTERED_SCANNERS.append(scanner)
    return scanner


def get_registered_scanners() -> list[BaseScanner]:
    """Return a copy of the currently registered scanners."""
    return list(_REGISTERED_SCANNERS)


def register_scanners(scanners: Iterable[BaseScanner]) -> None:
    """Register multiple scanners in one call."""
    for scanner in scanners:
        register_scanner(scanner)


register_scanner(SecretScanner())
register_scanner(FileRiskScanner())
