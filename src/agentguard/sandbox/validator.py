"""Sandbox policy validator.

Runs a scenario suite through the Guard, computes aggregate metrics
(TPR, FPR, accuracy), and produces a ValidationReport.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from agentguard.sandbox.runner import run_suite

if TYPE_CHECKING:
    from agentguard.policies.guard import Guard
    from agentguard.sandbox.models import Scenario, ScenarioResult


@dataclass
class ValidationReport:
    """Aggregate validation metrics from running a scenario suite.

    Terminology:
        - True Positive (TP): scenario expected "deny", got "deny" (correctly caught)
        - False Positive (FP): scenario expected "allow", got "deny"
          (incorrectly blocked)
        - True Negative (TN): scenario expected "allow", got "allow" (correctly allowed)
        - False Negative (FN): scenario expected "deny", got "allow" (missed threat)

    Attributes:
        total: Total number of scenarios.
        passed: Number of scenarios that matched expected outcome.
        failed: Number of scenarios that did not match.
        true_positives: Correctly denied scenarios.
        false_positives: Incorrectly denied scenarios.
        true_negatives: Correctly allowed scenarios.
        false_negatives: Incorrectly allowed scenarios.
        results: Individual ScenarioResult objects.
    """

    total: int
    passed: int
    failed: int
    true_positives: int
    false_positives: int
    true_negatives: int
    false_negatives: int
    results: list[ScenarioResult] = field(default_factory=list)

    @property
    def accuracy(self) -> float:
        """Overall accuracy: (TP + TN) / total."""
        if self.total == 0:
            return 1.0
        return self.passed / self.total

    @property
    def true_positive_rate(self) -> float:
        """TPR (recall/sensitivity): TP / (TP + FN).

        Returns 1.0 when there are no deny scenarios (vacuously true).
        """
        denom = self.true_positives + self.false_negatives
        if denom == 0:
            return 1.0
        return self.true_positives / denom

    @property
    def false_positive_rate(self) -> float:
        """FPR: FP / (FP + TN).

        Returns 0.0 when there are no allow scenarios.
        """
        denom = self.false_positives + self.true_negatives
        if denom == 0:
            return 0.0
        return self.false_positives / denom

    def to_dict(self) -> dict[str, Any]:
        """Convert to a dictionary for serialization."""
        return {
            "total": self.total,
            "passed": self.passed,
            "failed": self.failed,
            "true_positives": self.true_positives,
            "false_positives": self.false_positives,
            "true_negatives": self.true_negatives,
            "false_negatives": self.false_negatives,
            "accuracy": self.accuracy,
            "true_positive_rate": self.true_positive_rate,
            "false_positive_rate": self.false_positive_rate,
        }


def validate(
    scenarios: list[Scenario],
    guard: Guard,
) -> ValidationReport:
    """Run all scenarios and produce a validation report.

    Args:
        scenarios: List of scenarios to validate against.
        guard: The Guard instance with loaded policies.

    Returns:
        A ValidationReport with aggregate metrics.
    """
    results = run_suite(scenarios, guard)

    tp = fn = tn = fp = 0
    for result in results:
        if result.expected == "deny":
            if result.actual == "deny":
                tp += 1
            else:
                fn += 1
        else:  # expected == "allow"
            if result.actual == "allow":
                tn += 1
            else:
                fp += 1

    passed = sum(1 for r in results if r.passed)
    failed = len(results) - passed

    return ValidationReport(
        total=len(results),
        passed=passed,
        failed=failed,
        true_positives=tp,
        false_positives=fp,
        true_negatives=tn,
        false_negatives=fn,
        results=results,
    )
