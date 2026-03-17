"""Tests for the sandbox policy validator.

The validator runs a scenario suite, computes aggregate metrics
(TPR, FPR, accuracy), and produces a ValidationReport.
"""

from __future__ import annotations

import pytest

from agentguard.policies.guard import Guard


class TestValidationReport:
    """Tests for the ValidationReport data model."""

    def test_perfect_report(self) -> None:
        """100% accuracy with no false positives or negatives."""
        from agentguard.sandbox.validator import ValidationReport

        report = ValidationReport(
            total=10,
            passed=10,
            failed=0,
            true_positives=5,
            false_positives=0,
            true_negatives=5,
            false_negatives=0,
        )
        assert report.accuracy == 1.0
        assert report.true_positive_rate == 1.0
        assert report.false_positive_rate == 0.0

    def test_report_with_false_positives(self) -> None:
        """FPR should reflect false positives / (false positives + true negatives)."""
        from agentguard.sandbox.validator import ValidationReport

        report = ValidationReport(
            total=10,
            passed=8,
            failed=2,
            true_positives=5,
            false_positives=2,
            true_negatives=3,
            false_negatives=0,
        )
        assert report.false_positive_rate == pytest.approx(2 / 5)  # 2 / (2 + 3)
        assert report.true_positive_rate == 1.0  # 5 / (5 + 0)

    def test_report_with_false_negatives(self) -> None:
        """TPR should reflect true positives / (true positives + false negatives)."""
        from agentguard.sandbox.validator import ValidationReport

        report = ValidationReport(
            total=10,
            passed=7,
            failed=3,
            true_positives=2,
            false_positives=0,
            true_negatives=5,
            false_negatives=3,
        )
        assert report.true_positive_rate == pytest.approx(2 / 5)  # 2 / (2 + 3)
        assert report.false_positive_rate == 0.0

    def test_report_accuracy(self) -> None:
        from agentguard.sandbox.validator import ValidationReport

        report = ValidationReport(
            total=20,
            passed=16,
            failed=4,
            true_positives=8,
            false_positives=2,
            true_negatives=8,
            false_negatives=2,
        )
        assert report.accuracy == pytest.approx(16 / 20)

    def test_report_handles_zero_denominators(self) -> None:
        """When there are no deny scenarios, TPR should be 1.0 (vacuously true)."""
        from agentguard.sandbox.validator import ValidationReport

        report = ValidationReport(
            total=5,
            passed=5,
            failed=0,
            true_positives=0,
            false_positives=0,
            true_negatives=5,
            false_negatives=0,
        )
        # No deny scenarios → TPR is vacuously 1.0
        assert report.true_positive_rate == 1.0
        # No allow scenarios in the negative sense → FPR is 0.0
        assert report.false_positive_rate == 0.0

    def test_report_to_dict(self) -> None:
        from agentguard.sandbox.validator import ValidationReport

        report = ValidationReport(
            total=4,
            passed=3,
            failed=1,
            true_positives=2,
            false_positives=1,
            true_negatives=1,
            false_negatives=0,
        )
        d = report.to_dict()
        assert d["total"] == 4
        assert d["passed"] == 3
        assert d["failed"] == 1
        assert "accuracy" in d
        assert "true_positive_rate" in d
        assert "false_positive_rate" in d


class TestValidateFunction:
    """Tests for the validate() function that runs scenarios and produces a report."""

    def test_validate_with_no_policies(self) -> None:
        """With no policies, all 'allow' scenarios pass, all 'deny' scenarios fail."""
        from agentguard.sandbox.models import Scenario, ScenarioAction
        from agentguard.sandbox.validator import validate

        scenarios = [
            Scenario(
                name="benign",
                description="Benign action",
                expected_outcome="allow",
                actions=[ScenarioAction(kind="file_read", params={"path": "/tmp/x"})],
            ),
            Scenario(
                name="malicious",
                description="Should be caught",
                expected_outcome="deny",
                actions=[
                    ScenarioAction(
                        kind="file_write",
                        params={"content": "sk-proj-AAAAAAAAAAAAAAAAAAAAAA1234567890"},
                    ),
                ],
            ),
        ]
        guard = Guard()
        report = validate(scenarios, guard)
        assert report.total == 2
        assert report.passed == 1  # benign passes
        assert report.failed == 1  # malicious is a false negative
        assert report.false_negatives == 1
        assert report.true_negatives == 1

    def test_validate_with_good_policies(self) -> None:
        """With proper policies, both allow and deny scenarios pass."""
        from agentguard.sandbox.models import Scenario, ScenarioAction
        from agentguard.sandbox.validator import validate

        scenarios = [
            Scenario(
                name="benign-read",
                description="Read a file",
                expected_outcome="allow",
                actions=[ScenarioAction(kind="file_read", params={"path": "/tmp/x"})],
            ),
            Scenario(
                name="catch-api-key",
                description="Catch real API key in file write",
                expected_outcome="deny",
                actions=[
                    ScenarioAction(
                        kind="file_write",
                        params={"content": "API_KEY = supersecretkey12345678901"},
                    ),
                ],
            ),
        ]
        guard = Guard()
        guard.load_policy_file(
            "src/agentguard/policies/builtin_policies/no-secret-exposure.yaml"
        )
        report = validate(scenarios, guard)
        assert report.total == 2
        assert report.passed == 2
        assert report.accuracy == 1.0

    def test_validate_empty_suite(self) -> None:
        from agentguard.sandbox.validator import validate

        report = validate([], Guard())
        assert report.total == 0
        assert report.passed == 0

    def test_validate_results_attribute(self) -> None:
        """The report should contain individual ScenarioResults."""
        from agentguard.sandbox.models import Scenario, ScenarioAction
        from agentguard.sandbox.validator import validate

        scenarios = [
            Scenario(
                name="s1",
                description="test",
                expected_outcome="allow",
                actions=[ScenarioAction(kind="file_read", params={"path": "/tmp/x"})],
            ),
        ]
        report = validate(scenarios, Guard())
        assert len(report.results) == 1
        assert report.results[0].scenario_name == "s1"
