import io
import os
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = PROJECT_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from devguard.cli import main
from devguard.models import Finding
from devguard.scan import scan_project


class DevGuardCliIntegrationTests(unittest.TestCase):
    def test_scan_project_returns_empty_list_for_clean_directory(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            result = scan_project(temp_dir, scanners=[])
            self.assertEqual(result, [])

    def test_scan_project_uses_registered_scanners_by_default(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            manifest = Path(temp_dir) / "requirements.txt"
            manifest.write_text("flask\nrequests\n", encoding="utf-8")

            findings = scan_project(temp_dir)

            self.assertTrue(any(f.rule == "DEPENDENCY_MANIFEST" for f in findings))

    def test_scan_project_accepts_empty_scanner_list(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            manifest = Path(temp_dir) / "requirements.txt"
            manifest.write_text("flask\nrequests\n", encoding="utf-8")

            findings = scan_project(temp_dir, scanners=[])

            self.assertEqual(findings, [])

    def test_scan_project_uses_shared_finding_contract(self):
        finding = Finding(
            file="config.py",
            line=12,
            rule="HARDCODED_SECRET",
            severity="HIGH",
            message="Possible hardcoded secret detected",
        )

        self.assertEqual(finding.file, "config.py")
        self.assertEqual(finding.line, 12)
        self.assertEqual(finding.rule, "HARDCODED_SECRET")
        self.assertEqual(finding.severity, "HIGH")
        self.assertEqual(finding.message, "Possible hardcoded secret detected")

    def test_registered_scanners_work_together_with_multiple_findings(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            (root / ".env").write_text("SECRET_KEY=demo\n", encoding="utf-8")
            (root / "requirements.txt").write_text("flask\n", encoding="utf-8")

            findings = scan_project(root)
            rules = {finding.rule for finding in findings}

            self.assertIn("SENSITIVE_FILE", rules)
            self.assertIn("DEPENDENCY_MANIFEST", rules)

    def test_cli_scan_prints_summary_for_valid_directory(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                exit_code = main(["scan", temp_dir])
            output = stdout.getvalue()

            self.assertEqual(exit_code, 0)
            self.assertIn("DevGuard Security Scan", output)
            self.assertIn("Security Scan Summary", output)

    def test_cli_scan_returns_non_zero_for_missing_directory(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            missing = Path(temp_dir) / "missing-project"
            exit_code = main(["scan", str(missing)])
            self.assertNotEqual(exit_code, 0)

    def test_package_entrypoint_runs(self):
        env = os.environ.copy()
        env["PYTHONPATH"] = str(PROJECT_ROOT / "src") + os.pathsep + env.get("PYTHONPATH", "")

        with tempfile.TemporaryDirectory() as temp_dir:
            completed = subprocess.run(
                [sys.executable, "-m", "devguard", "scan", temp_dir],
                capture_output=True,
                text=True,
                cwd=str(PROJECT_ROOT),
                env=env,
            )

            self.assertEqual(completed.returncode, 0)


if __name__ == "__main__":
    unittest.main()
