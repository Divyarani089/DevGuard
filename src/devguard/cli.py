"""Command-line interface for DevGuard."""

from __future__ import annotations

import argparse
import sys
from typing import Sequence

from .reporting import _safe_terminal_text, format_summary, print_findings
from .scan import scan_project


def build_parser() -> argparse.ArgumentParser:
    """Create the CLI parser."""
    parser = argparse.ArgumentParser(
        prog="devguard",
        description="DevGuard security scanner for source-code projects",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser("scan", help="Scan a project directory")
    scan_parser.add_argument("path", help="Project path to scan")
    return parser


def _print_banner() -> None:
    """Render the DevGuard banner."""
    banner = (
        "╭─────────────────────────────────────────────╮\n"
        "│              DevGuard Security Scan         │\n"
        "╰─────────────────────────────────────────────╯"
    )
    print(_safe_terminal_text(banner))
    print()


def main(argv: Sequence[str] | None = None) -> int:
    """Entry point used by the CLI and tests."""
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "scan":
        return _handle_scan(args.path)

    parser.error(f"Unsupported command: {args.command}")
    return 2


def _handle_scan(project_path: str) -> int:
    """Validate the path and run the project scan."""
    try:
        _print_banner()
        findings = scan_project(project_path)
        print_findings(findings)
        print(format_summary(findings))
        return 0 if not findings else 1
    except (FileNotFoundError, NotADirectoryError, PermissionError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2
    except RuntimeError as exc:
        print(f"Scanner error: {exc}", file=sys.stderr)
        return 3
    except Exception as exc:  # pragma: no cover - defensive fallback
        print(f"Unexpected error: {exc}", file=sys.stderr)
        return 4


if __name__ == "__main__":
    raise SystemExit(main())
