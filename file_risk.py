"""
DevGuard - File Risk Analysis

Detects potentially sensitive files using Python Standard Library only.
"""

import fnmatch
import os
from pathlib import Path


# Directories that usually contain generated/dependency files.
# Skipping them keeps scanning fast and avoids unnecessary findings.
DEFAULT_IGNORED_DIRECTORIES = {
    ".git",
    "__pycache__",
    "node_modules",
    ".venv",
    "venv",
    "env",
    "build",
    "dist",
}


# Filename-based security rules.
# We deliberately use specific filenames/patterns instead of
# marking every file with an extension such as .json as dangerous.
SENSITIVE_FILE_RULES = [
    {
        "patterns": [".env", ".env.*"],
        "severity": "CRITICAL",
        "message": "Sensitive environment file detected",
    },
    {
        "patterns": [
            "id_rsa",
            "id_dsa",
            "id_ecdsa",
            "id_ed25519",
        ],
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


# These are normally example/template files and should not be treated
# as real secret files.
SAFE_ENV_TEMPLATES = {
    ".env.example",
    ".env.sample",
    ".env.template",
}


def _match_rule(filename):
    """
    Find the security rule that matches a filename.

    Matching is case-insensitive.

    Returns:
        dict or None: Matching rule, or None if the file is not risky.
    """
    filename = filename.lower()

    # Avoid false positives for common environment templates.
    if filename in SAFE_ENV_TEMPLATES:
        return None

    for rule in SENSITIVE_FILE_RULES:
        for pattern in rule["patterns"]:
            if fnmatch.fnmatchcase(filename, pattern.lower()):
                return rule

    return None


def analyze_file(file_path):
    """
    Analyze a single file for filename-based security risks.

    Args:
        file_path: Path to the file being analyzed.

    Returns:
        list[dict]: List of DevGuard findings.
    """
    path = Path(file_path)

    # Directories are not individual files to analyze.
    if path.is_dir():
        return []

    # Do not follow symbolic links.
    # This prevents scanning files outside the project accidentally.
    if path.is_symlink():
        return []

    rule = _match_rule(path.name)

    if rule is None:
        return []

    return [
        {
            "file": str(path),
            "line": None,
            "rule": "SENSITIVE_FILE",
            "severity": rule["severity"],
            "message": rule["message"],
        }
    ]


def scan_file_risks(project_path, ignored_directories=None):
    """
    Recursively scan a project for sensitive files.

    Args:
        project_path: Root directory of the project.
        ignored_directories: Optional collection of directory names
            that should not be scanned.

    Returns:
        list[dict]: Security findings.
    """
    root = Path(project_path)

    # Invalid or missing project paths should not crash DevGuard.
    if not root.exists() or not root.is_dir():
        return []

    if ignored_directories is None:
        ignored = DEFAULT_IGNORED_DIRECTORIES
    else:
        ignored = set(ignored_directories)

    findings = []
    seen_files = set()

    def handle_walk_error(error):
        """
        Ignore filesystem errors such as permission errors.

        One inaccessible directory should not stop the entire scan.
        """
        return None

    for current_root, directories, filenames in os.walk(
        root,
        topdown=True,
        followlinks=False,
        onerror=handle_walk_error,
    ):
        current_path = Path(current_root)

        # Prevent traversal into ignored directories and symlinked
        # directories.
        directories[:] = [
            directory
            for directory in directories
            if directory not in ignored
            and not (current_path / directory).is_symlink()
        ]

        for filename in filenames:
            file_path = current_path / filename

            # Resolve the path for duplicate detection.
            try:
                unique_path = str(file_path.resolve(strict=False))
            except OSError:
                unique_path = os.path.normcase(
                    os.path.abspath(file_path)
                )

            if unique_path in seen_files:
                continue

            seen_files.add(unique_path)

            findings.extend(analyze_file(file_path))

    return findings