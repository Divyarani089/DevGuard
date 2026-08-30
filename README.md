# DevGuard

DevGuard is a lightweight, zero-dependency Python security scanner for codebases and dependency manifests. It is built with the Python standard library only and provides a small, plugin-friendly scanner framework around a shared `Finding` data contract.

## Project overview

DevGuard currently includes three built-in scanners:

- `SecretScanner`: detects hardcoded secrets and private-key material in source files.
- `FileRiskScanner`: detects sensitive filenames such as `.env`, `.env.*`, SSH keys, and credential containers.
- `DependencyScanner`: detects project dependency manifests and records declared dependencies without claiming vulnerability status.

## Features

- Zero-dependency implementation using only the Python standard library
- Standardized `Finding` objects with:
  - `file`
  - `line`
  - `rule`
  - `severity`
  - `message`
- Scanner registry and project-level orchestration via `scan_project()`
- File, fixture, and project-directory exclusions to reduce false positives
- CLI-based scanning with exit codes suitable for automation

## Zero-dependency requirement

This project intentionally does not rely on external packages, pip installs, or third-party security libraries. The implementation and tests are restricted to the Python standard library.

## Project structure

```text
DevGuard/
├── README.md
├── pyproject.toml
├── src/
│   └── devguard/
│       ├── __init__.py
│       ├── __main__.py
│       ├── cli.py
│       ├── dependency_analyzer.py
│       ├── file_risk.py
│       ├── interfaces.py
│       ├── models.py
│       ├── registry.py
│       ├── reporting.py
│       ├── scan.py
│       └── secret_detector.py
└── tests/
    ├── test_cli_integration.py
    ├── test_dependency_analyzer.py
    ├── test_file_risk.py
    └── test_secret_detector.py
```

## How to run the CLI

From the project root:

```bash
python -m devguard scan .
```

Example:

```bash
$env:PYTHONPATH="src"
python -m devguard scan .
```

## Finding format

Each finding uses the shared `Finding` contract:

```python
Finding(
    file="path/to/file",
    line=12,
    rule="HARDCODED_SECRET",
    severity="HIGH",
    message="Possible hardcoded secret detected",
)
```

## SecretScanner

`SecretScanner` inspects source files for likely hardcoded credentials and private-key material. It skips binary files and obvious environment lookups such as `os.getenv(...)` or `os.environ[...]` and ignores fixture/test directories when scanning a project tree.

## FileRiskScanner

`FileRiskScanner` inspects file names and path patterns for sensitive project assets such as:

- `.env`, `.env.*`
- `id_rsa`, `id_dsa`, `id_ecdsa`, `id_ed25519`
- `*.key`
- `credentials.json`, `secrets.json`
- `*.pem`
- `*.p12`, `*.pfx`

Known safe templates such as `.env.example`, `.env.sample`, and `.env.template` are excluded.

## DependencyScanner

`DependencyScanner` analyzes recognized dependency manifest files and reports their presence as `DEPENDENCY_MANIFEST` findings. It does not claim vulnerability status. It only records declared dependencies and manifest detection.

### Supported dependency manifests

- `requirements.txt`
- `package.json`
- `go.mod`
- `Cargo.toml`
- `pom.xml`
- `.csproj`

## Test command

```bash
python -m unittest discover -s tests -v
```

## Notes

- The scanner registry is used by `scan_project()` when no explicit scanner list is provided.
- A caller may still pass `scanners=[]` to skip all scanners for a project scan.
- The project remains zero-dependency and uses only Python standard-library modules.
