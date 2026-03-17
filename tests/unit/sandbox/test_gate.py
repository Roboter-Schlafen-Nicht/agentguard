"""Tests for the sandbox gate (production readiness check).

The gate takes a ValidationReport and thresholds, and returns
a pass/fail verdict with reasons.
"""

from __future__ import annotations


class TestGateVerdict:
    """Tests for the GateVerdict data model."""

    def test_passing_verdict(self) -> None:
        from agentguard.sandbox.gate import GateVerdict

        verdict = GateVerdict(passed=True, reasons=[])
        assert verdict.passed is True
        assert verdict.reasons == []

    def test_failing_verdict_with_reasons(self) -> None:
        from agentguard.sandbox.gate import GateVerdict

        verdict = GateVerdict(
            passed=False,
            reasons=["FPR too high: 0.15 > 0.05", "TPR too low: 0.80 < 0.95"],
        )
        assert verdict.passed is False
        assert len(verdict.reasons) == 2


class TestGateThresholds:
    """Tests for the GateThresholds configuration."""

    def test_default_thresholds(self) -> None:
        from agentguard.sandbox.gate import GateThresholds

        t = GateThresholds()
        assert t.min_tpr == 0.95
        assert t.max_fpr == 0.05
        assert t.max_consecutive_denials == 2
        assert t.min_accuracy == 0.90

    def test_custom_thresholds(self) -> None:
        from agentguard.sandbox.gate import GateThresholds

        t = GateThresholds(min_tpr=0.99, max_fpr=0.01, max_consecutive_denials=1)
        assert t.min_tpr == 0.99
        assert t.max_fpr == 0.01
        assert t.max_consecutive_denials == 1


class TestCheckGate:
    """Tests for the check_gate() function."""

    def test_passes_perfect_report(self) -> None:
        from agentguard.sandbox.gate import GateThresholds, check_gate
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
        verdict = check_gate(report, GateThresholds())
        assert verdict.passed is True

    def test_fails_when_fpr_too_high(self) -> None:
        from agentguard.sandbox.gate import GateThresholds, check_gate
        from agentguard.sandbox.validator import ValidationReport

        report = ValidationReport(
            total=10,
            passed=7,
            failed=3,
            true_positives=5,
            false_positives=3,
            true_negatives=2,
            false_negatives=0,
        )
        verdict = check_gate(report, GateThresholds())
        assert verdict.passed is False
        assert any("false positive rate" in r.lower() for r in verdict.reasons)

    def test_fails_when_tpr_too_low(self) -> None:
        from agentguard.sandbox.gate import GateThresholds, check_gate
        from agentguard.sandbox.validator import ValidationReport

        report = ValidationReport(
            total=10,
            passed=6,
            failed=4,
            true_positives=1,
            false_positives=0,
            true_negatives=5,
            false_negatives=4,
        )
        verdict = check_gate(report, GateThresholds())
        assert verdict.passed is False
        assert any("true positive rate" in r.lower() for r in verdict.reasons)

    def test_fails_when_accuracy_too_low(self) -> None:
        from agentguard.sandbox.gate import GateThresholds, check_gate
        from agentguard.sandbox.validator import ValidationReport

        report = ValidationReport(
            total=10,
            passed=5,
            failed=5,
            true_positives=3,
            false_positives=3,
            true_negatives=2,
            false_negatives=2,
        )
        verdict = check_gate(report, GateThresholds(min_accuracy=0.90))
        assert verdict.passed is False
        assert any("accuracy" in r.lower() for r in verdict.reasons)

    def test_passes_with_relaxed_thresholds(self) -> None:
        from agentguard.sandbox.gate import GateThresholds, check_gate
        from agentguard.sandbox.validator import ValidationReport

        report = ValidationReport(
            total=10,
            passed=7,
            failed=3,
            true_positives=4,
            false_positives=1,
            true_negatives=3,
            false_negatives=2,
        )
        # Very relaxed thresholds
        thresholds = GateThresholds(min_tpr=0.5, max_fpr=0.5, min_accuracy=0.5)
        verdict = check_gate(report, thresholds)
        assert verdict.passed is True

    def test_empty_report_passes(self) -> None:
        """An empty report has no data to fail on — vacuously passes."""
        from agentguard.sandbox.gate import GateThresholds, check_gate
        from agentguard.sandbox.validator import ValidationReport

        report = ValidationReport(
            total=0,
            passed=0,
            failed=0,
            true_positives=0,
            false_positives=0,
            true_negatives=0,
            false_negatives=0,
        )
        verdict = check_gate(report, GateThresholds())
        assert verdict.passed is True

    def test_multiple_failure_reasons(self) -> None:
        """When multiple thresholds fail, all reasons should be included."""
        from agentguard.sandbox.gate import GateThresholds, check_gate
        from agentguard.sandbox.validator import ValidationReport

        report = ValidationReport(
            total=10,
            passed=2,
            failed=8,
            true_positives=1,
            false_positives=4,
            true_negatives=1,
            false_negatives=4,
        )
        verdict = check_gate(report, GateThresholds())
        assert verdict.passed is False
        assert len(verdict.reasons) >= 2  # At least TPR and FPR should fail

    def test_fails_when_feedback_loops_detected(self) -> None:
        """Gate should fail when feedback loop results exceed threshold."""
        from agentguard.sandbox.feedback import FeedbackLoopResult
        from agentguard.sandbox.gate import GateThresholds, check_gate
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
        # 4 consecutive denials (exceeds default threshold of 2)
        feedback_results = [
            FeedbackLoopResult(
                scenario_name="password-loop",
                turns=5,
                denials_per_turn=[1, 1, 1, 1, 0],
                max_consecutive_denials=4,
                has_feedback_loop=True,
            )
        ]
        verdict = check_gate(
            report, GateThresholds(), feedback_results=feedback_results
        )
        assert verdict.passed is False
        assert any(
            "feedback loop" in r.lower() or "consecutive denial" in r.lower()
            for r in verdict.reasons
        )

    def test_passes_when_feedback_loops_within_threshold(self) -> None:
        """Gate should pass when feedback loop results are within threshold."""
        from agentguard.sandbox.feedback import FeedbackLoopResult
        from agentguard.sandbox.gate import GateThresholds, check_gate
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
        # 2 consecutive denials, at threshold (max_consecutive_denials=2)
        feedback_results = [
            FeedbackLoopResult(
                scenario_name="single-retry",
                turns=5,
                denials_per_turn=[1, 1, 0, 0, 0],
                max_consecutive_denials=2,
                has_feedback_loop=False,
            )
        ]
        verdict = check_gate(
            report, GateThresholds(), feedback_results=feedback_results
        )
        assert verdict.passed is True

    def test_passes_without_feedback_results(self) -> None:
        """Gate passes when no feedback results are provided."""
        from agentguard.sandbox.gate import GateThresholds, check_gate
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
        # No feedback_results parameter at all
        verdict = check_gate(report, GateThresholds())
        assert verdict.passed is True

    def test_fails_when_any_feedback_loop_exceeds_threshold(self) -> None:
        """If any single prompt triggers a feedback loop, the gate fails."""
        from agentguard.sandbox.feedback import FeedbackLoopResult
        from agentguard.sandbox.gate import GateThresholds, check_gate
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
        feedback_results = [
            FeedbackLoopResult(
                scenario_name="benign",
                turns=5,
                denials_per_turn=[0, 0, 0, 0, 0],
                max_consecutive_denials=0,
                has_feedback_loop=False,
            ),
            FeedbackLoopResult(
                scenario_name="loop-trigger",
                turns=5,
                denials_per_turn=[1, 1, 1, 1, 1],
                max_consecutive_denials=5,
                has_feedback_loop=True,
            ),
        ]
        verdict = check_gate(
            report, GateThresholds(), feedback_results=feedback_results
        )
        assert verdict.passed is False
        assert any("loop-trigger" in r for r in verdict.reasons)
