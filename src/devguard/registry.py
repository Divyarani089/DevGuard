from __future__ import annotations

from typing import Iterable

from .interfaces import BaseScanner
from .secret_detector import SecretScanner

_REGISTERED_SCANNERS: list[BaseScanner] = []


def register_scanner(scanner: BaseScanner) -> None:
    """Register a scanner instance."""
    _REGISTERED_SCANNERS.append(scanner)


def get_registered_scanners() -> list[BaseScanner]:
    """Return all registered scanners."""
    return list(_REGISTERED_SCANNERS)


def register_scanners(scanners: Iterable[BaseScanner]) -> None:
    """Register multiple scanners at once."""
    for scanner in scanners:
        register_scanner(scanner)


register_scanner(SecretScanner())