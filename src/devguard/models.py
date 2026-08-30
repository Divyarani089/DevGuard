"""Shared models used across DevGuard scanners and the CLI."""

from __future__ import annotations

from dataclasses import asdict, dataclass


@dataclass(frozen=True)
class Finding:
    """Standardized security finding returned by every scanner module."""

    file: str
    line: int
    rule: str
    severity: str
    message: str

    def to_dict(self) -> dict[str, str | int]:
        """Return a dictionary representation for serialization and logging."""
        data = asdict(self)
        data["severity"] = str(data["severity"]).upper()
        return data

    @classmethod
    def from_dict(cls, payload: dict[str, object]) -> "Finding":
        """Build a Finding instance from a mapping."""
        return cls(
            file=str(payload.get("file", "")),
            line=int(payload.get("line", 1)),
            rule=str(payload.get("rule", "UNKNOWN_RULE")),
            severity=str(payload.get("severity", "LOW")).upper(),
            message=str(payload.get("message", "Security issue detected")),
        )
