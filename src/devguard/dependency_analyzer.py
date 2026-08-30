"""Dependency analysis for DevGuard.

This module preserves the original dependency parsing logic while integrating it
into the DevGuard scanner architecture.
"""

from __future__ import annotations

import json
import os
import re
import tomllib
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Sequence

from .interfaces import BaseScanner
from .models import Finding


MANIFEST_RULES = {
    "requirements.txt": "Python",
    "package.json": "JavaScript/Node.js",
    "go.mod": "Go",
    "cargo.toml": "Rust",
    "pom.xml": "Java",
}


IGNORED_DIRECTORIES = {
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


def detect_manifest_type(file_path):
    """Identify the project type from a manifest filename."""
    path = Path(file_path)
    name = path.name.lower()

    if name in MANIFEST_RULES:
        return MANIFEST_RULES[name]

    if path.suffix.lower() == ".csproj":
        return "C#/.NET"

    return None


def _normalize_dependency_name(value):
    """Extract a package name from common dependency formats."""
    value = value.strip()

    if not value or value.startswith(("#", "//")):
        return None

    match = re.match(r"^[A-Za-z0-9_.-]+", value)

    if match:
        return match.group(0)

    return None


def _parse_requirements(file_path):
    """Extract dependencies from requirements.txt."""
    dependencies = []

    try:
        content = Path(file_path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return dependencies

    for line in content.splitlines():
        line = line.strip()

        if not line or line.startswith("#"):
            continue

        if line.startswith("-"):
            continue

        dependency = _normalize_dependency_name(line)

        if dependency:
            dependencies.append(dependency)

    return dependencies


def _parse_package_json(file_path):
    """Extract dependencies from package.json."""
    try:
        with Path(file_path).open("r", encoding="utf-8") as file:
            data = json.load(file)
    except (OSError, json.JSONDecodeError):
        return []

    if not isinstance(data, dict):
        return []

    dependencies = []

    for section in ("dependencies", "devDependencies"):
        values = data.get(section, {})

        if not isinstance(values, dict):
            continue

        dependencies.extend(values.keys())

    return dependencies


def _parse_go_mod(file_path):
    """Extract dependencies from go.mod."""
    dependencies = []

    try:
        content = Path(file_path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return dependencies

    in_require_block = False

    for line in content.splitlines():
        stripped = line.strip()

        if stripped.startswith("require ("):
            in_require_block = True
            continue

        if in_require_block and stripped == ")":
            in_require_block = False
            continue

        if in_require_block:
            parts = stripped.split()

            if parts and not parts[0].startswith("//"):
                dependencies.append(parts[0])

        elif stripped.startswith("require "):
            parts = stripped.split()

            if len(parts) >= 2:
                dependencies.append(parts[1])

    return dependencies


def _parse_cargo_toml(file_path):
    """Extract dependencies from Cargo.toml."""
    try:
        with Path(file_path).open("rb") as file:
            data = tomllib.load(file)
    except (OSError, tomllib.TOMLDecodeError):
        return []

    dependencies = []

    for section_name in ("dependencies", "dev-dependencies"):
        section = data.get(section_name, {})

        if isinstance(section, dict):
            dependencies.extend(section.keys())

    return dependencies


def _parse_pom_xml(file_path):
    """Extract dependency artifact IDs from pom.xml."""
    dependencies = []

    try:
        tree = ET.parse(file_path)
        root = tree.getroot()
    except (OSError, ET.ParseError):
        return dependencies

    for dependency in root.iter():
        if not dependency.tag.endswith("dependency"):
            continue

        for child in dependency:
            if child.tag.endswith("artifactId"):
                if child.text:
                    dependencies.append(child.text.strip())
                break

    return dependencies


def _parse_csproj(file_path):
    """Extract PackageReference names from a .csproj file."""
    dependencies = []

    try:
        tree = ET.parse(file_path)
        root = tree.getroot()
    except (OSError, ET.ParseError):
        return dependencies

    for element in root.iter():
        if not element.tag.endswith("PackageReference"):
            continue

        include = element.attrib.get("Include")

        if include:
            dependencies.append(include)

    return dependencies


def _extract_dependencies(file_path):
    """Select the appropriate dependency parser based on the manifest filename."""
    path = Path(file_path)
    name = path.name.lower()

    if name == "requirements.txt":
        return _parse_requirements(path)

    if name == "package.json":
        return _parse_package_json(path)

    if name == "go.mod":
        return _parse_go_mod(path)

    if name == "cargo.toml":
        return _parse_cargo_toml(path)

    if name == "pom.xml":
        return _parse_pom_xml(path)

    if path.suffix.lower() == ".csproj":
        return _parse_csproj(path)

    return []


def _remove_duplicates(dependencies):
    """Remove duplicate dependency names while preserving order."""
    seen = set()
    result = []

    for dependency in dependencies:
        if dependency not in seen:
            seen.add(dependency)
            result.append(dependency)

    return result


def analyze_manifest(file_path):
    """Analyze one dependency manifest and return detailed dependency metadata."""
    path = Path(file_path)
    project_type = detect_manifest_type(path)

    if project_type is None:
        return None

    dependencies = _extract_dependencies(path)
    dependencies = _remove_duplicates(dependencies)

    return {
        "project_type": project_type,
        "manifest": str(path),
        "dependencies": dependencies,
        "total_dependencies": len(dependencies),
    }


def scan_dependencies(project_path):
    """Recursively find and analyze dependency manifests."""
    root = Path(project_path)

    if not root.exists() or not root.is_dir():
        return []

    results = []

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
            if directory not in IGNORED_DIRECTORIES
            and not (current_path / directory).is_symlink()
        ]

        for filename in filenames:
            file_path = current_path / filename

            if detect_manifest_type(file_path) is None:
                continue

            result = analyze_manifest(file_path)

            if result is not None:
                results.append(result)

    return results


class DependencyScanner(BaseScanner):
    """Scanner that reports detected dependency manifests without claiming vulnerabilities."""

    name = "dependency"

    def scan(self, project_path: str) -> Sequence[Finding]:
        """Scan a project and return manifest findings as standardized DevGuard findings."""
        root = Path(project_path).expanduser()

        if not root.is_dir():
            return []

        findings: list[Finding] = []

        for result in scan_dependencies(root):
            manifest = str(result.get("manifest", str(root)))
            project_type = str(result.get("project_type", "Unknown"))
            total_dependencies = int(result.get("total_dependencies", 0))
            message = (
                f"Dependency manifest detected for {project_type} project with "
                f"{total_dependencies} declared dependency(s)."
            )

            findings.append(
                Finding(
                    file=manifest,
                    line=1,
                    rule="DEPENDENCY_MANIFEST",
                    severity="LOW",
                    message=message,
                )
            )

        return findings
