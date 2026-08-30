"""High-level project scanning orchestration."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Iterable, Sequence

from .interfaces import BaseScanner
from .models import Finding
from .registry import get_registered_scanners

IGNORED_DIRECTORIES = {
    ".git",
    ".hg",
    ".svn",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    ".tox",
    ".venv",
    "venv",
    "env",
    "node_modules",
    "dist",
    "build",
    "site-packages",
    ".idea",
    ".vscode",
    "tests",
    "testdata",
    "fixtures",
    "mock",
    "mocks",
}


def _iter_project_files(project_root: Path) -> Iterable[Path]:
    """Yield files under a project while skipping unnecessary directories."""
    for current, dirnames, filenames in os.walk(project_root):
        dirnames[:] = [
            dirname for dirname in dirnames if dirname not in IGNORED_DIRECTORIES
        ]
        for filename in filenames:
            yield Path(current) / filename


def scan_project(project_path: str, scanners: Sequence[BaseScanner] | None = None) -> list[Finding]:
    """Run all registered scanners against a project directory.

    The CLI remains independent of individual scanner implementations and only
    depends on the common Finding contract.
    """
    root = Path(project_path).expanduser()
    if not root.exists():
        raise FileNotFoundError(f"Project path does not exist: {root}")
    if not root.is_dir():
        raise NotADirectoryError(f"Project path is not a directory: {root}")
    if not os.access(root, os.R_OK):
        raise PermissionError(f"Permission denied while reading project path: {root}")

    selected_scanners = list(scanners) if scanners is not None else get_registered_scanners()
    findings: list[Finding] = []

    for scanner in selected_scanners:
        scanner_name = getattr(scanner, "name", type(scanner).__name__)
        try:
            raw_results = scanner.scan(str(root))
        except Exception as exc:  # pragma: no cover - error path is surfaced to CLI
            raise RuntimeError(f"Scanner '{scanner_name}' failed: {exc}") from exc

        if raw_results is None:
            continue

        for item in raw_results:
            if isinstance(item, Finding):
                findings.append(item)
            elif isinstance(item, dict):
                findings.append(Finding.from_dict(item))
            else:
                raise TypeError(
                    f"Scanner '{scanner_name}' returned an invalid finding object: {type(item)!r}"
                )

    return findings
