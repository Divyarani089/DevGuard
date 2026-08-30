import json
import sys
import tempfile
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = PROJECT_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from devguard.dependency_analyzer import (
    DependencyScanner,
    analyze_manifest,
    detect_manifest_type,
    scan_dependencies,
)
from devguard.registry import get_registered_scanners
from devguard.scan import scan_project


class TestManifestDetection(unittest.TestCase):

    def test_requirements_txt_is_python(self):
        self.assertEqual(
            detect_manifest_type("requirements.txt"),
            "Python",
        )

    def test_package_json_is_javascript(self):
        self.assertEqual(
            detect_manifest_type("package.json"),
            "JavaScript/Node.js",
        )

    def test_go_mod_is_go(self):
        self.assertEqual(
            detect_manifest_type("go.mod"),
            "Go",
        )

    def test_cargo_toml_is_rust(self):
        self.assertEqual(
            detect_manifest_type("Cargo.toml"),
            "Rust",
        )

    def test_pom_xml_is_java(self):
        self.assertEqual(
            detect_manifest_type("pom.xml"),
            "Java",
        )

    def test_csproj_is_dotnet(self):
        self.assertEqual(
            detect_manifest_type("MyApp.csproj"),
            "C#/.NET",
        )

    def test_unknown_file_returns_none(self):
        self.assertIsNone(
            detect_manifest_type("README.md")
        )


class TestRequirementsParser(unittest.TestCase):

    def test_requirements_dependencies(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "requirements.txt"

            path.write_text(
                """
                flask
                requests>=2.31
                numpy==1.26.0
                # comment
                """,
                encoding="utf-8",
            )

            result = analyze_manifest(path)

            self.assertEqual(result["project_type"], "Python")
            self.assertEqual(
                result["dependencies"],
                ["flask", "requests", "numpy"],
            )
            self.assertEqual(result["total_dependencies"], 3)

    def test_requirements_duplicate_dependencies(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "requirements.txt"

            path.write_text(
                """
                flask
                requests
                flask
                requests>=2.0
                """,
                encoding="utf-8",
            )

            result = analyze_manifest(path)

            self.assertEqual(
                result["dependencies"],
                ["flask", "requests"],
            )
            self.assertEqual(result["total_dependencies"], 2)

    def test_empty_requirements(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "requirements.txt"
            path.write_text("", encoding="utf-8")

            result = analyze_manifest(path)

            self.assertEqual(result["dependencies"], [])
            self.assertEqual(result["total_dependencies"], 0)


class TestPackageJsonParser(unittest.TestCase):

    def test_package_json_dependencies(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "package.json"

            data = {
                "dependencies": {
                    "express": "^4.18.0",
                    "axios": "^1.0.0",
                },
                "devDependencies": {
                    "jest": "^29.0.0",
                },
            }

            path.write_text(
                json.dumps(data),
                encoding="utf-8",
            )

            result = analyze_manifest(path)

            self.assertEqual(
                result["dependencies"],
                ["express", "axios", "jest"],
            )
            self.assertEqual(result["total_dependencies"], 3)

    def test_malformed_package_json(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "package.json"

            path.write_text(
                '{"dependencies": ',
                encoding="utf-8",
            )

            result = analyze_manifest(path)

            self.assertEqual(result["dependencies"], [])
            self.assertEqual(result["total_dependencies"], 0)

    def test_empty_package_json(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "package.json"
            path.write_text("{}", encoding="utf-8")

            result = analyze_manifest(path)

            self.assertEqual(result["dependencies"], [])
            self.assertEqual(result["total_dependencies"], 0)


class TestGoModParser(unittest.TestCase):

    def test_go_mod_dependencies(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "go.mod"

            path.write_text(
                """
                module example.com/myapp

                require github.com/gin-gonic/gin v1.9.0

                require (
                    github.com/stretchr/testify v1.8.0
                    golang.org/x/text v0.9.0
                )
                """,
                encoding="utf-8",
            )

            result = analyze_manifest(path)

            self.assertEqual(
                result["dependencies"],
                [
                    "github.com/gin-gonic/gin",
                    "github.com/stretchr/testify",
                    "golang.org/x/text",
                ],
            )
            self.assertEqual(result["total_dependencies"], 3)


class TestCargoParser(unittest.TestCase):

    def test_cargo_dependencies(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "Cargo.toml"

            path.write_text(
                """
                [package]
                name = "demo"

                [dependencies]
                serde = "1.0"
                tokio = "1.0"

                [dev-dependencies]
                criterion = "0.5"
                """,
                encoding="utf-8",
            )

            result = analyze_manifest(path)

            self.assertEqual(
                result["dependencies"],
                ["serde", "tokio", "criterion"],
            )
            self.assertEqual(result["total_dependencies"], 3)

    def test_malformed_cargo_toml(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "Cargo.toml"

            path.write_text(
                "[dependencies\ninvalid",
                encoding="utf-8",
            )

            result = analyze_manifest(path)

            self.assertEqual(result["dependencies"], [])
            self.assertEqual(result["total_dependencies"], 0)


class TestPomParser(unittest.TestCase):

    def test_pom_dependencies(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "pom.xml"

            content = """<?xml version="1.0" encoding="UTF-8"?>
            <project>
                <dependencies>
                    <dependency>
                        <groupId>org.example</groupId>
                        <artifactId>spring-core</artifactId>
                        <version>1.0</version>
                    </dependency>
                    <dependency>
                        <groupId>org.example</groupId>
                        <artifactId>junit</artifactId>
                        <version>5.0</version>
                    </dependency>
                </dependencies>
            </project>
            """

            path.write_text(content, encoding="utf-8")

            result = analyze_manifest(path)

            self.assertEqual(
                result["dependencies"],
                ["spring-core", "junit"],
            )
            self.assertEqual(result["total_dependencies"], 2)

    def test_malformed_pom(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "pom.xml"

            path.write_text(
                "<project><dependencies>",
                encoding="utf-8",
            )

            result = analyze_manifest(path)

            self.assertEqual(result["dependencies"], [])


class TestCsprojParser(unittest.TestCase):

    def test_csproj_dependencies(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "Demo.csproj"

            content = """<Project Sdk="Microsoft.NET.Sdk">
                <ItemGroup>
                    <PackageReference Include="Newtonsoft.Json"
                                      Version="13.0.0" />
                    <PackageReference Include="Serilog"
                                      Version="3.0.0" />
                </ItemGroup>
            </Project>
            """

            path.write_text(content, encoding="utf-8")

            result = analyze_manifest(path)

            self.assertEqual(
                result["dependencies"],
                ["Newtonsoft.Json", "Serilog"],
            )
            self.assertEqual(result["total_dependencies"], 2)


class TestDependencyScanning(unittest.TestCase):

    def test_nested_manifest_is_detected(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)

            backend = root / "backend"
            backend.mkdir()

            manifest = backend / "requirements.txt"
            manifest.write_text(
                "flask\nrequests\n",
                encoding="utf-8",
            )

            results = scan_dependencies(root)

            self.assertEqual(len(results), 1)
            self.assertEqual(
                results[0]["project_type"],
                "Python",
            )

    def test_ignored_directory_is_not_scanned(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)

            node_modules = root / "node_modules"
            node_modules.mkdir()

            manifest = node_modules / "package.json"
            manifest.write_text(
                '{"dependencies": {"express": "^4.0.0"}}',
                encoding="utf-8",
            )

            results = scan_dependencies(root)

            self.assertEqual(results, [])

    def test_missing_project_returns_empty_list(self):
        results = scan_dependencies(
            "directory_that_does_not_exist"
        )

        self.assertEqual(results, [])


class TestDependencyScannerIntegration(unittest.TestCase):
    def test_dependency_scanner_detects_requirements_manifest(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            manifest = root / "requirements.txt"
            manifest.write_text("flask\nrequests\n", encoding="utf-8")

            findings = scan_project(root, scanners=[DependencyScanner()])

            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0].rule, "DEPENDENCY_MANIFEST")
            self.assertEqual(findings[0].severity, "LOW")

    def test_dependency_scanner_is_registered(self):
        scanner_names = [type(scanner).__name__ for scanner in get_registered_scanners()]
        self.assertIn("DependencyScanner", scanner_names)

    def test_scan_project_uses_registered_dependency_scanner(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            manifest = root / "package.json"
            manifest.write_text('{"dependencies": {"express": "^4.0.0"}}', encoding="utf-8")

            findings = scan_project(root)
            self.assertTrue(any(f.rule == "DEPENDENCY_MANIFEST" for f in findings))


if __name__ == "__main__":
    unittest.main()