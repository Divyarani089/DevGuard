"""Deterministic developer remediation recommendations for DevGuard findings."""

from __future__ import annotations

from devguard.models import Finding


RECOMMENDATIONS: dict[str, str] = {
    "HARDCODED_SECRET": (
        "Move the secret to an environment variable or a secure secret manager. "
        "Do not store secrets directly in source code."
    ),
    "API_KEY": (
        "Move the API key out of source code and store it in an environment "
        "variable or secure secret manager."
    ),
    "API_TOKEN": (
        "Move the API token out of source code and store it securely using "
        "environment variables or a secret manager."
    ),
    "ACCESS_TOKEN": (
        "Remove the access token from source code and store it securely. "
        "Rotate the token if it has been exposed."
    ),
    "AUTH_TOKEN": (
        "Remove the authentication token from source code and store it "
        "securely using an environment variable or secret manager."
    ),
    "PRIVATE_KEY": (
        "Remove the private key from the repository and rotate or revoke "
        "the key if it has been exposed."
    ),
    "SECRET_KEY": (
        "Move the secret key to an environment variable or secure secret "
        "manager instead of storing it in source code."
    ),
    "SENSITIVE_FILE": (
        "Do not commit sensitive files such as .env files. Add appropriate "
        "patterns to .gitignore and use environment variables for secrets."
    ),
    "DEPENDENCY_MANIFEST": (
        "Review declared dependencies and keep dependency versions "
        "controlled and up to date."
    ),
}


def get_recommendation(finding: Finding) -> str:
    """Return a deterministic remediation recommendation for a Finding.

    Unknown rules return a generic message rather than inventing a
    vulnerability or remediation.
    """
    rule = finding.rule.strip().upper()

    return RECOMMENDATIONS.get(
        rule,
        "Review this finding and determine the appropriate remediation "
        "based on the reported issue.",
    )