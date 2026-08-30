from __future__ import annotations

from pathlib import Path
from typing import Iterable, Sequence

from .interfaces import BaseScanner
from .models import Finding
from .registry import get_registered_scanners


IGNORED_DIRECTORIES = {
    ".git",
    "__pycache__",
    "node_modules",
    "venv",
    ".venv",
    "env",
    ".env",
    "build",
    "dist",
    ".tox",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    "site-packages",
    ".idea",
    ".vscode",
    "tests",
    "testdata",
    "fixtures",
    "mock",
    "mocks",
}


def iter_project_files(project_path: Path) -> Iterable[Path]:
    """Yield files that should be scanned."""
    for path in project_path.rglob("*"):
        if not path.is_file():
            continue

        if any(part in IGNORED_DIRECTORIES for part in path.parts):
            continue

        yield path


def scan_project(
    project_path: str | Path,
    scanners: Sequence[BaseScanner] | None = None,
) -> list[Finding]:
    """
    Scan a project directory using the registered scanners or an explicit collection.

    This preserves the intended architecture: scanners receive a project path and
    return standardized Finding objects.
    """
    root = Path(project_path).expanduser()

    if not root.exists():
        raise FileNotFoundError(f"Project path does not exist: {root}")

    if not root.is_dir():
        raise NotADirectoryError(f"Project path is not a directory: {root}")

    selected_scanners = list(scanners) if scanners is not None else get_registered_scanners()
    findings: list[Finding] = []

    for scanner in selected_scanners:
        scanner_name = getattr(scanner, "name", type(scanner).__name__)

        try:
            raw_results = scanner.scan(str(root))
        except Exception as exc:  # pragma: no cover - surfaced to CLI
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
                    f"Scanner '{scanner_name}' returned an unsupported finding type: {type(item).__name__}"
                )

    return findings