"""Registry that allows scanner modules to register themselves."""

from __future__ import annotations

from typing import Iterable

from .interfaces import BaseScanner
from .secret_detector import SecretScanner
_REGISTERED_SCANNERS: list[BaseScanner] = []


def register_scanner(scanner: BaseScanner) -> BaseScanner:
    """Register a scanner implementation.

    This keeps the CLI decoupled from the concrete implementation while allowing
    future scanners to plug in without any direct imports in the CLI layer.
    """
    if scanner not in _REGISTERED_SCANNERS:
        _REGISTERED_SCANNERS.append(scanner)
    return scanner


def get_registered_scanners() -> list[BaseScanner]:
    """Return a copy of the current registered scanners."""
    return list(_REGISTERED_SCANNERS)


def clear_registered_scanners() -> None:
    """Reset the registry, mainly used in tests."""
    _REGISTERED_SCANNERS.clear()


def register_scanners(scanners: Iterable[BaseScanner]) -> None:
    """Register multiple scanners at once."""
    for scanner in scanners:
        register_scanner(scanner)
register_scanner(SecretScanner())