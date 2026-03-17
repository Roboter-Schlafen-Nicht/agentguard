"""Sandbox production readiness gate.

Defines thresholds and a check function that determines whether
a policy configuration is ready for production deployment.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from agentguard.sandbox.feedback import FeedbackLoopResult
    from agentguard.sandbox.validator import ValidationReport


@dataclass
class GateThresholds:
    """Configurable thresholds for the production readiness gate.

    Attributes:
        min_tpr: Minimum true positive rate (default 0.95).
        max_fpr: Maximum false positive rate (default 0.05).
        max_consecutive_denials: Maximum allowed consecutive denials
            in feedback loop detection (default 2).
        min_accuracy: Minimum overall accuracy (default 0.90).
    """

    min_tpr: float = 0.95
    max_fpr: float = 0.05
    max_consecutive_denials: int = 2
    min_accuracy: float = 0.90


@dataclass
class GateVerdict:
    """Result of a production readiness gate check.

    Attributes:
        passed: Whether the configuration passed all thresholds.
        reasons: List of reasons for failure (empty if passed).
    """

    passed: bool
    reasons: list[str] = field(default_factory=list)


def check_gate(
    report: ValidationReport,
    thresholds: GateThresholds,
    *,
    feedback_results: list[FeedbackLoopResult] | None = None,
) -> GateVerdict:
    """Check if a validation report meets production readiness thresholds.

    Args:
        report: The validation report from running scenarios.
        thresholds: The thresholds to check against.
        feedback_results: Optional feedback loop simulation results.
            If provided, any prompt with max_consecutive_denials exceeding
            the threshold will fail the gate.

    Returns:
        A GateVerdict indicating pass/fail with reasons.
    """
    if report.total == 0 and not feedback_results:
        return GateVerdict(passed=True)

    reasons: list[str] = []

    if report.total > 0:
        if report.true_positive_rate < thresholds.min_tpr:
            reasons.append(
                f"True positive rate too low: {report.true_positive_rate:.3f} "
                f"< {thresholds.min_tpr:.3f}"
            )

        if report.false_positive_rate > thresholds.max_fpr:
            reasons.append(
                f"False positive rate too high: {report.false_positive_rate:.3f} "
                f"> {thresholds.max_fpr:.3f}"
            )

        if report.accuracy < thresholds.min_accuracy:
            reasons.append(
                f"Accuracy too low: {report.accuracy:.3f} "
                f"< {thresholds.min_accuracy:.3f}"
            )

    if feedback_results:
        for result in feedback_results:
            if result.max_consecutive_denials > thresholds.max_consecutive_denials:
                reasons.append(
                    f"Feedback loop detected in '{result.scenario_name}': "
                    f"{result.max_consecutive_denials} consecutive denials "
                    f"> {thresholds.max_consecutive_denials}"
                )

    return GateVerdict(passed=len(reasons) == 0, reasons=reasons)
