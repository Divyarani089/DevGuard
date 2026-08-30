import sys
import tempfile
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = PROJECT_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from devguard.secret_detector import SecretScanner, scan_file


class TestSecretDetector(unittest.TestCase):

    def create_temp_file(self, content):
        temp = tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            delete=False,
            suffix=".py",
        )

        temp.write(content)
        temp.close()

        return Path(temp.name)

    def test_hardcoded_password(self):
        file_path = self.create_temp_file(
            'password = "SuperSecret123"\n'
        )

        try:
            findings = scan_file(file_path)

            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0]["rule"], "HARDCODED_SECRET")
            self.assertEqual(findings[0]["severity"], "HIGH")
            self.assertEqual(findings[0]["line"], 1)
        finally:
            file_path.unlink(missing_ok=True)

    def test_api_key(self):
        file_path = self.create_temp_file(
            'API_KEY = "fake_api_key_123456"\n'
        )

        try:
            findings = scan_file(file_path)

            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0]["rule"], "API_KEY")
            self.assertEqual(findings[0]["severity"], "HIGH")
            self.assertEqual(findings[0]["line"], 1)
        finally:
            file_path.unlink(missing_ok=True)

    def test_access_token(self):
        file_path = self.create_temp_file(
            'access_token = "fake_access_token_123"\n'
        )

        try:
            findings = scan_file(file_path)

            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0]["rule"], "ACCESS_TOKEN")
            self.assertEqual(findings[0]["severity"], "HIGH")
        finally:
            file_path.unlink(missing_ok=True)

    def test_private_key(self):
        file_path = self.create_temp_file(
            "-----BEGIN PRIVATE KEY-----\n"
            "fake-private-key-data\n"
            "-----END PRIVATE KEY-----\n"
        )

        try:
            findings = scan_file(file_path)

            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0]["rule"], "PRIVATE_KEY")
            self.assertEqual(findings[0]["severity"], "CRITICAL")
            self.assertEqual(findings[0]["line"], 1)
        finally:
            file_path.unlink(missing_ok=True)

    def test_environment_variable_is_not_flagged(self):
        file_path = self.create_temp_file(
            "import os\n"
            'password = os.getenv("PASSWORD")\n'
            'API_KEY = os.environ["API_KEY"]\n'
        )

        try:
            findings = scan_file(file_path)

            self.assertEqual(findings, [])
        finally:
            file_path.unlink(missing_ok=True)

    def test_comment_is_not_flagged(self):
        file_path = self.create_temp_file(
            '# password = "SuperSecret123"\n'
        )

        try:
            findings = scan_file(file_path)

            self.assertEqual(findings, [])
        finally:
            file_path.unlink(missing_ok=True)

    def test_empty_file(self):
        file_path = self.create_temp_file("")

        try:
            findings = scan_file(file_path)

            self.assertEqual(findings, [])
        finally:
            file_path.unlink(missing_ok=True)

    def test_api_token(self):
        file_path = self.create_temp_file(
            'API_TOKEN = "fake_api_token_123"\n'
        )

        try:
            findings = scan_file(file_path)

            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0]["rule"], "API_TOKEN")
            self.assertEqual(findings[0]["severity"], "HIGH")
        finally:
            file_path.unlink(missing_ok=True)

    def test_auth_token(self):
        file_path = self.create_temp_file(
            'auth_token = "fake_auth_token_123"\n'
        )

        try:
            findings = scan_file(file_path)

            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0]["rule"], "AUTH_TOKEN")
            self.assertEqual(findings[0]["severity"], "HIGH")
        finally:
            file_path.unlink(missing_ok=True)

    def test_secret_key(self):
        file_path = self.create_temp_file(
            'SECRET_KEY = "fake_secret_key_123"\n'
        )

        try:
            findings = scan_file(file_path)

            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0]["rule"], "SECRET_KEY")
            self.assertEqual(findings[0]["severity"], "HIGH")
        finally:
            file_path.unlink(missing_ok=True)

    def test_multiple_secrets(self):
        file_path = self.create_temp_file(
            'password = "Secret123"\n'
            'API_KEY = "fake_key_123"\n'
            'access_token = "fake_token_123"\n'
        )

        try:
            findings = scan_file(file_path)

            self.assertEqual(len(findings), 3)

            self.assertEqual(findings[0]["line"], 1)
            self.assertEqual(findings[1]["line"], 2)
            self.assertEqual(findings[2]["line"], 3)
        finally:
            file_path.unlink(missing_ok=True)

    def test_missing_file(self):
        file_path = Path("this_file_does_not_exist.py")

        findings = scan_file(file_path)

        self.assertEqual(findings, [])

    def test_binary_file_is_ignored(self):
        with tempfile.NamedTemporaryFile(
            mode="wb",
            delete=False,
            suffix=".bin",
        ) as temp:
            temp.write(b"\x00\x01\x02\x03password\x00\xff")
            file_path = Path(temp.name)

        try:
            findings = scan_file(file_path)

            self.assertEqual(findings, [])
        finally:
            file_path.unlink(missing_ok=True)

    def test_invalid_encoding_is_ignored(self):
        with tempfile.NamedTemporaryFile(
            mode="wb",
            delete=False,
            suffix=".py",
        ) as temp:
            temp.write(b"\xff\xfe\xfa\xfb")
            file_path = Path(temp.name)

        try:
            findings = scan_file(file_path)

            self.assertEqual(findings, [])
        finally:
            file_path.unlink(missing_ok=True)

    def test_large_file(self):
        content = ("normal_code = True\n" * 10000) + (
            'password = "LargeFileSecret123"\n'
        )

        file_path = self.create_temp_file(content)

        try:
            findings = scan_file(file_path)

            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0]["rule"], "HARDCODED_SECRET")
            self.assertEqual(findings[0]["severity"], "HIGH")
            self.assertEqual(findings[0]["line"], 10001)
        finally:
            file_path.unlink(missing_ok=True)

    def test_fixture_directories_are_ignored_but_docs_and_examples_are_not(self):
        project_root = Path(tempfile.mkdtemp())

        try:
            for directory_name in ["tests", "testdata", "fixtures", "mock", "mocks"]:
                (project_root / directory_name).mkdir()

            (project_root / "docs").mkdir()
            (project_root / "examples").mkdir()

            (project_root / "tests" / "test_example.py").write_text(
                'password = "should_be_ignored"\n',
                encoding="utf-8",
            )
            (project_root / "testdata" / "fixture.txt").write_text(
                "API_KEY=ignored\n",
                encoding="utf-8",
            )
            (project_root / "fixtures" / "sample.env").write_text(
                "SECRET_KEY=ignored\n",
                encoding="utf-8",
            )
            (project_root / "mock" / "mocked.py").write_text(
                "access_token = 'ignored'\n",
                encoding="utf-8",
            )
            (project_root / "mocks" / "x.py").write_text(
                "auth_token = 'ignored'\n",
                encoding="utf-8",
            )
            (project_root / "docs" / "guide.md").write_text(
                "API_KEY = 'doc_example'\n",
                encoding="utf-8",
            )
            (project_root / "examples" / "sample.py").write_text(
                "SECRET_KEY = 'example_value'\n",
                encoding="utf-8",
            )

            scanner = SecretScanner()
            findings = scanner.scan(str(project_root))

            self.assertEqual(len(findings), 2)
            self.assertEqual({finding.file for finding in findings}, {
                str(project_root / "docs" / "guide.md"),
                str(project_root / "examples" / "sample.py"),
            })
        finally:
            for path in sorted(project_root.rglob("*"), reverse=True):
                if path.is_file() or path.is_symlink():
                    path.unlink(missing_ok=True)
                elif path.is_dir():
                    path.rmdir()

if __name__ == "__main__":
    unittest.main()