import sys
import tempfile
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = PROJECT_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from devguard.file_risk import FileRiskScanner, analyze_file, scan_file_risks
from devguard.scan import scan_project


class TestAnalyzeFile(unittest.TestCase):

    def test_env_file_is_critical(self):
        result = analyze_file(".env")

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["rule"], "SENSITIVE_FILE")
        self.assertEqual(result[0]["severity"], "CRITICAL")
        self.assertIsNone(result[0]["line"])

    def test_env_local_is_critical(self):
        result = analyze_file(".env.local")

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["severity"], "CRITICAL")

    def test_env_example_is_not_flagged(self):
        result = analyze_file(".env.example")

        self.assertEqual(result, [])

    def test_credentials_json_is_high(self):
        result = analyze_file("credentials.json")

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["severity"], "HIGH")

    def test_secrets_json_is_high(self):
        result = analyze_file("secrets.json")

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["severity"], "HIGH")

    def test_ssh_private_key_is_critical(self):
        result = analyze_file("id_rsa")

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["severity"], "CRITICAL")

    def test_key_file_is_critical(self):
        result = analyze_file("private.key")

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["severity"], "CRITICAL")

    def test_pem_file_is_high(self):
        result = analyze_file("certificate.pem")

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["severity"], "HIGH")

    def test_p12_file_is_high(self):
        result = analyze_file("certificate.p12")

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["severity"], "HIGH")

    def test_normal_json_is_not_flagged(self):
        result = analyze_file("config.json")

        self.assertEqual(result, [])

    def test_readme_is_not_flagged(self):
        result = analyze_file("README.md")

        self.assertEqual(result, [])

    def test_directory_is_not_analyzed(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            directory = Path(temp_dir) / ".env"
            directory.mkdir()

            result = analyze_file(directory)

            self.assertEqual(result, [])


class TestScanFileRisks(unittest.TestCase):

    def test_nested_sensitive_file_is_detected(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)

            nested_dir = root / "config"
            nested_dir.mkdir()

            env_file = nested_dir / ".env"
            env_file.write_text("SECRET=test")

            result = scan_file_risks(root)

            self.assertEqual(len(result), 1)
            self.assertEqual(result[0]["severity"], "CRITICAL")
            self.assertEqual(result[0]["rule"], "SENSITIVE_FILE")

    def test_ignored_directory_is_not_scanned(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)

            git_dir = root / ".git"
            git_dir.mkdir()

            env_file = git_dir / ".env"
            env_file.write_text("SECRET=test")

            result = scan_file_risks(root)

            self.assertEqual(result, [])

    def test_missing_project_returns_empty_list(self):
        result = scan_file_risks("directory_that_does_not_exist")

        self.assertEqual(result, [])

    def test_normal_files_are_not_reported(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)

            (root / "app.py").write_text("print('hello')")
            (root / "README.md").write_text("# Project")
            (root / "config.json").write_text("{}")

            result = scan_file_risks(root)

            self.assertEqual(result, [])

    def test_multiple_sensitive_files_are_detected(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)

            (root / ".env").write_text("SECRET=test")
            (root / "credentials.json").write_text("{}")
            (root / "id_rsa").write_text("PRIVATE KEY")

            result = scan_file_risks(root)

            self.assertEqual(len(result), 3)

            severities = {finding["severity"] for finding in result}

            self.assertIn("CRITICAL", severities)
            self.assertIn("HIGH", severities)


class TestFileRiskIntegration(unittest.TestCase):
    def test_scanner_is_registered_and_used_by_scan_project(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            (root / ".env").write_text("SECRET=test", encoding="utf-8")
            (root / "normal.txt").write_text("clean text", encoding="utf-8")

            findings = scan_project(root)

            self.assertTrue(any(f.rule == "SENSITIVE_FILE" for f in findings))
            self.assertFalse(any(f.file.endswith("normal.txt") for f in findings))

    def test_scanner_handles_explicit_custom_scanners(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            (root / "credentials.json").write_text("{}", encoding="utf-8")

            findings = scan_project(root, scanners=[FileRiskScanner()])

            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0].rule, "SENSITIVE_FILE")


if __name__ == "__main__":
    unittest.main()