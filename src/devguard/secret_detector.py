"""Secret detection scanner for DevGuard."""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Sequence

from .interfaces import BaseScanner
from .models import Finding


SECRET_ASSIGNMENT_PATTERN = re.compile(
    r"""
    (?P<name>
        password
        |passwd
        |pwd
        |db_password
        |api_key
        |api_token
        |secret_key
        |access_token
        |auth_token
        |private_key
        |client_secret
    )
    \s*
    (?:=|:)
    \s*
    (?P<value>
        ["']
        (?P<quoted_value>.*?)
        ["']
        |
        [^\s#]+
    )
    """,
    re.IGNORECASE | re.VERBOSE,
)


PRIVATE_KEY_PATTERN = re.compile(
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----"
)


PLACEHOLDER_VALUES = {
    "",
    "password",
    "passwd",
    "password123",
    "your_password",
    "your_password_here",
    "your_api_key",
    "your_api_token",
    "your_secret_key",
    "your_token",
    "example",
    "example123",
    "dummy",
    "dummy123",
    "changeme",
    "change_me",
    "test",
    "test123",
    "none",
    "null",
}


IGNORED_DIRECTORIES = {
    ".git",
    "__pycache__",
    ".venv",
    "venv",
    "env",
    "node_modules",
    "dist",
    "build",
}


def _is_binary_file(file_path: Path) -> bool:
    """Return True when the file appears to contain binary data."""
    try:
        with file_path.open("rb") as file:
            chunk = file.read(8192)
    except (OSError, PermissionError):
        return False

    return b"\x00" in chunk


def _is_placeholder(value: str) -> bool:
    """Return True for obvious example or placeholder values."""
    normalized = value.strip().lower()

    if normalized in PLACEHOLDER_VALUES:
        return True

    if normalized.startswith("${") and normalized.endswith("}"):
        return True

    if normalized.startswith("<") and normalized.endswith(">"):
        return True

    return False


def _looks_like_environment_lookup(value: str) -> bool:
    """Return True when the value comes from an environment lookup."""
    normalized = value.lower()

    environment_patterns = (
        "os.getenv(",
        "os.environ[",
        "os.environ.get(",
        "getenv(",
        "environ[",
        "${",
    )

    return any(pattern in normalized for pattern in environment_patterns)


def _get_rule(name: str) -> tuple[str, str]:
    """Map a secret-like variable name to a rule and severity."""
    normalized = name.lower()

    if normalized == "private_key":
        return "PRIVATE_KEY", "CRITICAL"

    if "password" in normalized or normalized in {"passwd", "pwd"}:
        return "HARDCODED_SECRET", "HIGH"

    if "api_key" in normalized:
        return "API_KEY", "HIGH"

    if "api_token" in normalized:
        return "API_TOKEN", "HIGH"

    if "access_token" in normalized:
        return "ACCESS_TOKEN", "HIGH"

    if "auth_token" in normalized:
        return "AUTH_TOKEN", "HIGH"

    if "secret_key" in normalized:
        return "SECRET_KEY", "HIGH"

    if "client_secret" in normalized:
        return "CLIENT_SECRET", "HIGH"

    return "HARDCODED_SECRET", "HIGH"


def _message_for_rule(rule: str) -> str:
    """Return a human-readable message for a detection rule."""
    messages = {
        "HARDCODED_SECRET": "Possible hardcoded credential detected",
        "API_KEY": "Possible hardcoded API key detected",
        "API_TOKEN": "Possible hardcoded API token detected",
        "ACCESS_TOKEN": "Possible hardcoded access token detected",
        "AUTH_TOKEN": "Possible hardcoded authentication token detected",
        "SECRET_KEY": "Possible hardcoded secret key detected",
        "CLIENT_SECRET": "Possible hardcoded client secret detected",
    }

    return messages.get(rule, "Possible hardcoded secret detected")


def scan_file(file_path: str | Path) -> list[dict[str, str | int]]:
    """
    Scan one source file for potential exposed secrets.

    This helper preserves the original secret detector interface used by
    the unit tests. It returns dictionaries and does not print anything.
    """
    findings: list[dict[str, str | int]] = []
    file_path = Path(file_path)

    if not file_path.is_file():
        return findings

    if _is_binary_file(file_path):
        return findings

    try:
        with file_path.open(
            "r",
            encoding="utf-8",
            errors="strict",
        ) as file:
            for line_number, line in enumerate(file, start=1):
                stripped = line.strip()

                if not stripped:
                    continue

                if stripped.startswith("#"):
                    continue

                private_key_match = PRIVATE_KEY_PATTERN.search(line)

                if private_key_match:
                    findings.append(
                        {
                            "file": str(file_path),
                            "line": line_number,
                            "rule": "PRIVATE_KEY",
                            "severity": "CRITICAL",
                            "message": "Private key material detected",
                        }
                    )
                    continue

                matches = SECRET_ASSIGNMENT_PATTERN.finditer(line)

                for match in matches:
                    name = match.group("name")
                    value = match.group("quoted_value")

                    if value is None:
                        value = match.group("value")

                    value = value.strip()

                    if _is_placeholder(value):
                        continue

                    if _looks_like_environment_lookup(value):
                        continue

                    rule, severity = _get_rule(name)

                    findings.append(
                        {
                            "file": str(file_path),
                            "line": line_number,
                            "rule": rule,
                            "severity": severity,
                            "message": _message_for_rule(rule),
                        }
                    )

    except (OSError, PermissionError, UnicodeError):
        return []

    unique_findings: list[dict[str, str | int]] = []
    seen: set[tuple[str, int, str]] = set()

    for finding in findings:
        key = (
            str(finding["file"]),
            int(finding["line"]),
            str(finding["rule"]),
        )

        if key not in seen:
            seen.add(key)
            unique_findings.append(finding)

    return unique_findings


class SecretScanner(BaseScanner):
    """DevGuard scanner that detects hardcoded secrets."""

    name = "secret"

    def scan(self, project_path: str) -> Sequence[Finding]:
        """Scan all project files and return standardized Finding objects."""
        root = Path(project_path).expanduser()

        if not root.is_dir():
            return []

        findings: list[Finding] = []

        for current, dirnames, filenames in os.walk(root):
            dirnames[:] = [
                dirname
                for dirname in dirnames
                if dirname not in IGNORED_DIRECTORIES
            ]

            for filename in filenames:
                file_path = Path(current) / filename

                for item in scan_file(file_path):
                    findings.append(
                        Finding.from_dict(item)
                    )

        return findings