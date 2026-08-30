"""Tests for DevGuard remediation recommendations."""

import unittest

from devguard.models import Finding
from devguard.remediation.recommender import get_recommendation


class TestRecommendations(unittest.TestCase):

    def make_finding(self, rule: str) -> Finding:
        return Finding(
            file="example.py",
            line=10,
            rule=rule,
            severity="HIGH",
            message="Test finding",
        )

    def test_hardcoded_secret(self):
        recommendation = get_recommendation(
            self.make_finding("HARDCODED_SECRET")
        )
        self.assertIn("environment variable", recommendation)

    def test_api_key(self):
        recommendation = get_recommendation(
            self.make_finding("API_KEY")
        )
        self.assertIn("API key", recommendation)

    def test_api_token(self):
        recommendation = get_recommendation(
            self.make_finding("API_TOKEN")
        )
        self.assertIn("API token", recommendation)

    def test_access_token(self):
        recommendation = get_recommendation(
            self.make_finding("ACCESS_TOKEN")
        )
        self.assertIn("access token", recommendation)

    def test_auth_token(self):
        recommendation = get_recommendation(
            self.make_finding("AUTH_TOKEN")
        )
        self.assertIn("authentication token", recommendation)

    def test_private_key(self):
        recommendation = get_recommendation(
            self.make_finding("PRIVATE_KEY")
        )
        self.assertIn("private key", recommendation)

    def test_secret_key(self):
        recommendation = get_recommendation(
            self.make_finding("SECRET_KEY")
        )
        self.assertIn("secret key", recommendation)

    def test_sensitive_file(self):
        recommendation = get_recommendation(
            self.make_finding("SENSITIVE_FILE")
        )
        self.assertIn(".env", recommendation)

    def test_dependency_manifest(self):
        recommendation = get_recommendation(
            self.make_finding("DEPENDENCY_MANIFEST")
        )
        self.assertIn("dependencies", recommendation)

    def test_unknown_rule_does_not_invent_vulnerability(self):
        recommendation = get_recommendation(
            self.make_finding("UNKNOWN_RULE")
        )
        self.assertIn("Review this finding", recommendation)


if __name__ == "__main__":
    unittest.main()