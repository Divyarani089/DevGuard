import re
from pathlib import Path


# ---------------------------------------------------------------------------
# Secret Detection Rules
# ---------------------------------------------------------------------------

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


def _is_binary_file(file_path):
    """Return True when the file appears to contain binary data."""

    try:
        with open(file_path, "rb") as file:
            chunk = file.read(8192)
    except (OSError, PermissionError):
        return False

    return b"\x00" in chunk


def _is_placeholder(value):
    """Return True for obvious example or placeholder values."""

    normalized = value.strip().lower()

    if normalized in PLACEHOLDER_VALUES:
        return True

    if normalized.startswith("${") and normalized.endswith("}"):
        return True

    if normalized.startswith("<") and normalized.endswith(">"):
        return True

    return False


def _looks_like_environment_lookup(value):
    """Return True when the value comes from an environment/config lookup."""

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


def _get_rule(name):
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


def _create_finding(file_path, line_number, rule, severity, message):
    """Create a finding using the team's agreed output format."""

    return {
        "file": str(file_path),
        "line": line_number,
        "rule": rule,
        "severity": severity,
        "message": message,
    }


def scan_file(file_path):
    """
    Scan one source file for potential exposed secrets.

    Returns:
        list[dict]: Security findings.

    This function intentionally does not print anything.
    """

    findings = []
    file_path = Path(file_path)

    # ---------------------------------------------------------------
    # Basic file checks
    # ---------------------------------------------------------------

    if not file_path.is_file():
        return findings

    if _is_binary_file(file_path):
        return findings

    # ---------------------------------------------------------------
    # Scan line by line
    # ---------------------------------------------------------------

    try:
        with file_path.open(
            "r",
            encoding="utf-8",
            errors="strict",
        ) as file:

            for line_number, line in enumerate(file, start=1):

                stripped = line.strip()

                # Ignore completely empty lines.
                if not stripped:
                    continue

                # Ignore lines that are only comments.
                if stripped.startswith("#"):
                    continue

                # ---------------------------------------------------
                # Private key detection
                # ---------------------------------------------------

                private_key_match = PRIVATE_KEY_PATTERN.search(line)

                if private_key_match:
                    findings.append(
                        _create_finding(
                            file_path,
                            line_number,
                            "PRIVATE_KEY",
                            "CRITICAL",
                            "Private key material detected",
                        )
                    )

                    # Don't also classify this line as a generic secret.
                    continue

                # ---------------------------------------------------
                # Password/API key/token detection
                # ---------------------------------------------------

                matches = SECRET_ASSIGNMENT_PATTERN.finditer(line)

                for match in matches:
                    name = match.group("name")
                    value = match.group("quoted_value")

                    if value is None:
                        value = match.group("value")

                    value = value.strip()

                    # Avoid obvious placeholders.
                    if _is_placeholder(value):
                        continue

                    # Avoid values loaded from environment variables.
                    if _looks_like_environment_lookup(value):
                        continue

                    rule, severity = _get_rule(name)

                    if rule == "HARDCODED_SECRET":
                        message = "Possible hardcoded credential detected"
                    elif rule == "API_KEY":
                        message = "Possible hardcoded API key detected"
                    elif rule == "API_TOKEN":
                        message = "Possible hardcoded API token detected"
                    elif rule == "ACCESS_TOKEN":
                        message = "Possible hardcoded access token detected"
                    elif rule == "AUTH_TOKEN":
                        message = "Possible hardcoded authentication token detected"
                    elif rule == "SECRET_KEY":
                        message = "Possible hardcoded secret key detected"
                    elif rule == "CLIENT_SECRET":
                        message = "Possible hardcoded client secret detected"
                    else:
                        message = "Possible hardcoded secret detected"

                    findings.append(
                        _create_finding(
                            file_path,
                            line_number,
                            rule,
                            severity,
                            message,
                        )
                    )

    except (OSError, PermissionError, UnicodeError):
        # A scanner should not crash because one file cannot be read.
        return []

    # ---------------------------------------------------------------
    # Remove duplicate findings
    # ---------------------------------------------------------------

    unique_findings = []
    seen = set()

    for finding in findings:
        key = (
            finding["file"],
            finding["line"],
            finding["rule"],
        )

        if key not in seen:
            seen.add(key)
            unique_findings.append(finding)

    return unique_findings