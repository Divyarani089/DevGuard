"""Sensitive-file risk scanner for DevGuard."""

from __future__ import annotations

import fnmatch
import os
from pathlib import Path
from typing import Sequence

from .interfaces import BaseScanner
from .models import Finding

DEFAULT_IGNORED_DIRECTORIES = {
    ".git",
    "__pycache__",
    "node_modules",
    ".venv",
    "venv",
    "env",
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

SENSITIVE_FILE_RULES = [
    {
        "patterns": [".env", ".env.*"],
        "severity": "CRITICAL",
        "message": "Sensitive environment file detected",
    },
    {
        "patterns": ["id_rsa", "id_dsa", "id_ecdsa", "id_ed25519"],
        "severity": "CRITICAL",
        "message": "SSH private key file detected",
    },
    {
        "patterns": ["*.key"],
        "severity": "CRITICAL",
        "message": "Potential private key file detected",
    },
    {
        "patterns": ["credentials.json", "secrets.json"],
        "severity": "HIGH",
        "message": "Potential credential or secret file detected",
    },
    {
        "patterns": ["*.pem"],
        "severity": "HIGH",
        "message": "Potential private key or certificate file detected",
    },
    {
        "patterns": ["*.p12", "*.pfx"],
        "severity": "HIGH",
        "message": "Certificate/private-key container detected",
    },
]

SAFE_ENV_TEMPLATES = {".env.example", ".env.sample", ".env.template"}


def _match_rule(filename: str):
    """Return the matching sensitive-file rule or None."""
    filename = filename.lower()

    if filename in SAFE_ENV_TEMPLATES:
        return None

    for rule in SENSITIVE_FILE_RULES:
        for pattern in rule["patterns"]:
            if fnmatch.fnmatchcase(filename, pattern.lower()):
                return rule

    return None


def analyze_file(file_path: str | Path) -> list[dict[str, str | int | None]]:
    """Analyze a single file path for filename-based sensitive-file risks."""
    path = Path(file_path)

    if path.is_dir():
        return []

    if path.is_symlink():
        return []

    rule = _match_rule(path.name)

    if rule is None:
        return []

    return [{
        "file": str(path),
        "line": None,
        "rule": "SENSITIVE_FILE",
        "severity": rule["severity"],
        "message": rule["message"],
    }]


def scan_file_risks(project_path: str | Path, ignored_directories=None):
    """Recursively scan a project tree for sensitive files."""
    root = Path(project_path)

    if not root.exists() or not root.is_dir():
        return []

    ignored = set(DEFAULT_IGNORED_DIRECTORIES if ignored_directories is None else ignored_directories)
    findings: list[dict[str, str | int | None]] = []
    seen_files: set[str] = set()

    def handle_walk_error(_error):
        return None

    for current_root, directories, filenames in os.walk(
        root,
        topdown=True,
        followlinks=False,
        onerror=handle_walk_error,
    ):
        current_path = Path(current_root)

        directories[:] = [
            directory
            for directory in directories
            if directory not in ignored and not (current_path / directory).is_symlink()
        ]

        for filename in filenames:
            file_path = current_path / filename

            if file_path.is_symlink():
                continue

            try:
                unique_path = str(file_path.resolve(strict=False))
            except OSError:
                unique_path = os.path.normcase(os.path.abspath(str(file_path)))

            if unique_path in seen_files:
                continue

            seen_files.add(unique_path)
            findings.extend(analyze_file(file_path))

    return findings


class FileRiskScanner(BaseScanner):
    """Scanner for filenames and paths indicating sensitive project files."""

    name = "file_risk"

    def scan(self, project_path: str) -> Sequence[Finding]:
        """Scan a project directory and return normalized findings."""
        project_root = Path(project_path).expanduser()

        if not project_root.is_dir():
            return []

        findings: list[Finding] = []
        for item in scan_file_risks(project_root):
            findings.append(
                Finding(
                    file=str(item["file"]),
                    line=int(item["line"]) if item["line"] is not None else 1,
                    rule=str(item["rule"]),
                    severity=str(item["severity"]),
                    message=str(item["message"]),
                )
            )

        return findings
