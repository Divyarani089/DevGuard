"""Formatting helpers for CLI output."""

from __future__ import annotations

import sys
from collections import Counter

from .models import Finding


def _safe_terminal_text(text: str) -> str:
    """Return ASCII-safe output when the active terminal cannot render Unicode."""
    encoding = sys.stdout.encoding or "utf-8"
    try:
        text.encode(encoding)
        return text
    except UnicodeEncodeError:
        return text.encode("ascii", errors="replace").decode("ascii")


def format_finding(finding: Finding) -> str:
    """Render a single finding using the terminal-friendly format requested."""
    return _safe_terminal_text(
        f"[ {finding.severity} ] {finding.file}:{finding.line}\n"
        f"Rule: {finding.rule}\n"
        f"{finding.message}"
    )


def format_summary(findings: list[Finding]) -> str:
    """Summarize the counts of findings by severity."""
    counts = Counter(finding.severity.upper() for finding in findings)
    total = len(findings)
    separator = _safe_terminal_text("─────────────────────")
    summary = [
        "\nSecurity Scan Summary",
        separator,
        f"Total findings : {total}",
    ]

    for level in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        summary.append(f"{level:<15}: {counts.get(level, 0)}")

    return "\n".join(summary)


def print_findings(findings: list[Finding]) -> None:
    """Print findings in a human-friendly format, without exposing the secret values."""
    if not findings:
        print(_safe_terminal_text("No security issues found."))
        return

    for finding in findings:
        print(_safe_terminal_text(format_finding(finding)))
        print()
