"""Tests for DevGuard risk scoring and analytics."""

import unittest

from devguard.models import Finding
from devguard.risk_engine import (
    calculate_analytics,
    calculate_score,
    score_findings,
)


def make_finding(
    severity="LOW",
    rule="TEST_RULE",
):
    """Create a Finding for testing."""

    return Finding(
        file="test.py",
        line=1,
        rule=rule,
        severity=severity,
        message="Test finding",
    )


class TestCalculateScore(unittest.TestCase):

    def test_empty_findings_score_is_100(self):
        self.assertEqual(
            calculate_score([]),
            100,
        )

    def test_critical_penalty(self):
        self.assertEqual(
            calculate_score([
                make_finding("CRITICAL"),
            ]),
            70,
        )

    def test_high_penalty(self):
        self.assertEqual(
            calculate_score([
                make_finding("HIGH"),
            ]),
            85,
        )

    def test_medium_penalty(self):
        self.assertEqual(
            calculate_score([
                make_finding("MEDIUM"),
            ]),
            93,
        )

    def test_low_penalty(self):
        self.assertEqual(
            calculate_score([
                make_finding("LOW"),
            ]),
            98,
        )

    def test_multiple_severity_penalties(self):
        findings = [
            make_finding("CRITICAL"),
            make_finding("HIGH"),
            make_finding("MEDIUM"),
            make_finding("LOW"),
        ]

        # 100 - 30 - 15 - 7 - 2 = 46
        self.assertEqual(
            calculate_score(findings),
            46,
        )

    def test_score_cannot_go_below_zero(self):
        findings = [
            make_finding("CRITICAL")
            for _ in range(10)
        ]

        self.assertEqual(
            calculate_score(findings),
            0,
        )

    def test_lowercase_severity(self):
        self.assertEqual(
            calculate_score([
                make_finding("critical"),
            ]),
            70,
        )

    def test_unknown_severity_has_no_penalty(self):
        self.assertEqual(
            calculate_score([
                make_finding("UNKNOWN"),
            ]),
            100,
        )


class TestRiskLevels(unittest.TestCase):

    def test_low_risk(self):
        findings = [
            make_finding("LOW")
            for _ in range(5)
        ]

        result = calculate_analytics(findings)

        self.assertEqual(result["score"], 90)
        self.assertEqual(result["risk_level"], "LOW")

    def test_medium_risk(self):
        findings = [
            make_finding("HIGH"),
            make_finding("LOW"),
            make_finding("LOW"),
            make_finding("LOW"),
        ]

        result = calculate_analytics(findings)

        # 100 - 15 - 2 - 2 - 2 = 79
        self.assertEqual(result["score"], 79)
        self.assertEqual(result["risk_level"], "MEDIUM")

    def test_high_risk(self):
        findings = [
            make_finding("CRITICAL"),
            make_finding("HIGH"),
            make_finding("LOW"),
        ]

        result = calculate_analytics(findings)

        # 100 - 30 - 15 - 2 = 53
        self.assertEqual(result["score"], 53)
        self.assertEqual(result["risk_level"], "HIGH")

    def test_critical_risk(self):
        findings = [
            make_finding("CRITICAL"),
            make_finding("CRITICAL"),
            make_finding("CRITICAL"),
        ]

        result = calculate_analytics(findings)

        # 100 - 90 = 10
        self.assertEqual(result["score"], 10)
        self.assertEqual(result["risk_level"], "CRITICAL")


class TestSeverityAnalytics(unittest.TestCase):

    def test_severity_counts(self):
        findings = [
            make_finding("CRITICAL"),
            make_finding("HIGH"),
            make_finding("HIGH"),
            make_finding("MEDIUM"),
            make_finding("LOW"),
            make_finding("LOW"),
            make_finding("LOW"),
        ]

        result = calculate_analytics(findings)

        self.assertEqual(
            result["severity_counts"],
            {
                "CRITICAL": 1,
                "HIGH": 2,
                "MEDIUM": 1,
                "LOW": 3,
                "UNKNOWN": 0,
            },
        )


class TestScannerAnalytics(unittest.TestCase):

    def test_secret_scanner_count(self):
        findings = [
            make_finding("CRITICAL", "PRIVATE_KEY"),
            make_finding("HIGH", "HARDCODED_SECRET"),
            make_finding("HIGH", "SECRET_KEY"),
        ]

        result = calculate_analytics(findings)

        self.assertEqual(
            result["scanner_counts"]["Secret Scanner"],
            3,
        )

    def test_file_risk_scanner_count(self):
        findings = [
            make_finding(
                "CRITICAL",
                "SENSITIVE_FILE",
            )
        ]

        result = calculate_analytics(findings)

        self.assertEqual(
            result["scanner_counts"]["File Risk Scanner"],
            1,
        )

    def test_dependency_scanner_count(self):
        findings = [
            make_finding(
                "LOW",
                "DEPENDENCY_MANIFEST",
            )
        ]

        result = calculate_analytics(findings)

        self.assertEqual(
            result["scanner_counts"]["Dependency Scanner"],
            1,
        )

    def test_all_scanner_counts(self):
        findings = [
            make_finding("CRITICAL", "PRIVATE_KEY"),
            make_finding("HIGH", "HARDCODED_SECRET"),
            make_finding("HIGH", "SENSITIVE_FILE"),
            make_finding("LOW", "DEPENDENCY_MANIFEST"),
        ]

        result = calculate_analytics(findings)

        self.assertEqual(
            result["scanner_counts"],
            {
                "Secret Scanner": 2,
                "File Risk Scanner": 1,
                "Dependency Scanner": 1,
            },
        )


class TestRuleAnalytics(unittest.TestCase):

    def test_rule_counts(self):
        findings = [
            make_finding("HIGH", "SECRET_KEY"),
            make_finding("HIGH", "SECRET_KEY"),
            make_finding("CRITICAL", "PRIVATE_KEY"),
        ]

        result = calculate_analytics(findings)

        self.assertEqual(
            result["rule_counts"],
            {
                "SECRET_KEY": 2,
                "PRIVATE_KEY": 1,
            },
        )


class TestTotals(unittest.TestCase):

    def test_total_findings(self):
        findings = [
            make_finding("HIGH"),
            make_finding("MEDIUM"),
            make_finding("LOW"),
        ]

        result = calculate_analytics(findings)

        self.assertEqual(
            result["total_findings"],
            3,
        )

    def test_total_penalty(self):
        findings = [
            make_finding("CRITICAL"),
            make_finding("HIGH"),
            make_finding("LOW"),
        ]

        result = calculate_analytics(findings)

        # 30 + 15 + 2 = 47
        self.assertEqual(
            result["total_penalty"],
            47,
        )

    def test_empty_findings(self):
        result = calculate_analytics([])

        self.assertEqual(result["score"], 100)
        self.assertEqual(result["risk_level"], "LOW")
        self.assertEqual(result["total_findings"], 0)
        self.assertEqual(result["total_penalty"], 0)


class TestUnknownRules(unittest.TestCase):

    def test_unknown_rule_is_not_lost(self):
        result = calculate_analytics([
            make_finding(
                "HIGH",
                "NEW_UNKNOWN_RULE",
            )
        ])

        self.assertEqual(
            result["scanner_counts"],
            {
                "Unknown Scanner": 1,
            },
        )


class TestPublicAPI(unittest.TestCase):

    def test_score_findings_returns_analytics(self):
        findings = [
            make_finding("CRITICAL", "PRIVATE_KEY"),
            make_finding("HIGH", "SENSITIVE_FILE"),
        ]

        result = score_findings(findings)

        self.assertEqual(result["score"], 55)
        self.assertEqual(result["risk_level"], "HIGH")
        self.assertEqual(result["total_findings"], 2)


if __name__ == "__main__":
    unittest.main()