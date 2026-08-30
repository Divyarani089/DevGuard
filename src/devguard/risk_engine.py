"""DevGuard security risk scoring and analytics.

This module consumes the existing DevGuard Finding objects and produces
a deterministic, explainable security score and analytics.

Python Standard Library only.
"""

from __future__ import annotations

from collections import Counter
from typing import Iterable

from .models import Finding


# Penalty applied for every finding of each severity.
SEVERITY_PENALTIES = {
    "CRITICAL": 30,
    "HIGH": 15,
    "MEDIUM": 7,
    "LOW": 2,
}


# Existing DevGuard rules mapped to their scanner.
#
# We use the existing Finding.rule field instead of changing
# the Finding contract by adding a new "scanner" field.
RULE_SCANNERS = {
    # Secret Scanner
    "PRIVATE_KEY": "Secret Scanner",
    "HARDCODED_SECRET": "Secret Scanner",
    "SECRET_KEY": "Secret Scanner",
    "CLIENT_SECRET": "Secret Scanner",

    # File Risk Scanner
    "SENSITIVE_FILE": "File Risk Scanner",

    # Dependency Scanner
    "DEPENDENCY_MANIFEST": "Dependency Scanner",
}


def _risk_level(score: int) -> str:
    """Return the risk level corresponding to a security score."""

    if score >= 90:
        return "LOW"

    if score >= 70:
        return "MEDIUM"

    if score >= 40:
        return "HIGH"

    return "CRITICAL"


def _scanner_for_rule(rule: str) -> str:
    """Identify the scanner that produced a finding."""

    return RULE_SCANNERS.get(
        str(rule).upper(),
        "Unknown Scanner",
    )


def calculate_score(findings: Iterable[Finding]) -> int:
    """Calculate a deterministic security score from 0 to 100.

    The score starts at 100.

    CRITICAL -> -30
    HIGH     -> -15
    MEDIUM   -> -7
    LOW      -> -2

    The final score is always between 0 and 100.
    Unknown severities do not affect the score.
    """

    penalty = 0

    for finding in findings:
        severity = str(finding.severity).upper()
        penalty += SEVERITY_PENALTIES.get(severity, 0)

    return max(0, min(100, 100 - penalty))


def calculate_analytics(
    findings: Iterable[Finding],
) -> dict[str, object]:
    """Calculate the complete security analytics report.

    Returns:
        Dictionary containing:

        score
        risk_level
        severity_counts
        scanner_counts
        rule_counts
        total_findings
        total_penalty
    """

    findings = list(findings)

    severity_counts = Counter()
    scanner_counts = Counter()
    rule_counts = Counter()

    total_penalty = 0

    for finding in findings:
        severity = str(finding.severity).upper()
        rule = str(finding.rule).upper()

        severity_counts[severity] += 1
        rule_counts[rule] += 1

        scanner = _scanner_for_rule(rule)
        scanner_counts[scanner] += 1

        total_penalty += SEVERITY_PENALTIES.get(
            severity,
            0,
        )

    score = max(
        0,
        min(100, 100 - total_penalty),
    )

    return {
        "score": score,
        "risk_level": _risk_level(score),

        "severity_counts": {
            "CRITICAL": severity_counts.get("CRITICAL", 0),
            "HIGH": severity_counts.get("HIGH", 0),
            "MEDIUM": severity_counts.get("MEDIUM", 0),
            "LOW": severity_counts.get("LOW", 0),
            "UNKNOWN": severity_counts.get("UNKNOWN", 0),
        },

        "scanner_counts": dict(scanner_counts),

        "rule_counts": dict(rule_counts),

        "total_findings": len(findings),

        "total_penalty": total_penalty,
    }


def score_findings(
    findings: Iterable[Finding],
) -> dict[str, object]:
    """Public API for generating a DevGuard risk report."""

    return calculate_analytics(findings)