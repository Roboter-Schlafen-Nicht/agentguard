"""Conversation risk scoring — heuristic drift probability.

Analyzes a sequence of audit entries to compute a risk score
indicating the probability that an agent's behavior has drifted
from expected patterns. Higher scores indicate greater concern.

The scorer combines multiple heuristic signals:

- **High deny rate**: Many actions being blocked suggests the agent
  is attempting unauthorized operations.
- **Rapid action burst**: Unusually high action frequency may
  indicate runaway behavior.
- **Sensitive target access**: Attempts to access known sensitive
  files/paths (credentials, secrets, system files).
- **Error rate**: High error rates may indicate confused or
  malfunctioning behavior.
- **Repeated denials**: Same action/target being denied repeatedly
  suggests persistent unauthorized attempts.
- **Escalation pattern**: Severity of denials increasing over time
  suggests the agent is probing for weaknesses.

Usage::

    from agentguard.audit.risk import ConversationRiskScorer

    scorer = ConversationRiskScorer()
    score = scorer.score(audit_log.entries)
    print(f"Risk: {score.probability:.2f} ({score.level.value})")

    # Add to audit metadata
    metadata = score.to_metadata()
    # {"drift_probability": "0.73", "risk_level": "high", ...}
"""

from __future__ import annotations

import json
import logging
from collections import Counter
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from agentguard.audit.models import AuditEntry

logger = logging.getLogger(__name__)

#: Default patterns for sensitive file/path detection.
DEFAULT_SENSITIVE_PATTERNS: list[str] = [
    "/etc/passwd",
    "/etc/shadow",
    "/etc/sudoers",
    ".env",
    ".ssh/",
    "id_rsa",
    "id_ed25519",
    "credentials",
    "secret",
    "token",
    "password",
    "private_key",
    "aws_access_key",
    ".git/config",
]

#: Severity ordering for escalation detection.
_SEVERITY_ORDER: dict[str, int] = {
    "low": 0,
    "medium": 1,
    "high": 2,
    "critical": 3,
}


class SignalType(Enum):
    """Types of risk signals detected in audit data."""

    HIGH_DENY_RATE = "high_deny_rate"
    RAPID_ACTION_BURST = "rapid_action_burst"
    SENSITIVE_TARGET_ACCESS = "sensitive_target_access"
    ERROR_RATE = "error_rate"
    REPEATED_DENIALS = "repeated_denials"
    ESCALATION_PATTERN = "escalation_pattern"


class RiskLevel(Enum):
    """Classified risk level derived from probability."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @classmethod
    def from_probability(cls, probability: float) -> RiskLevel:
        """Classify a probability into a risk level.

        Thresholds:
        - [0.0, 0.25)  -> LOW
        - [0.25, 0.50) -> MEDIUM
        - [0.50, 0.75) -> HIGH
        - [0.75, 1.0]  -> CRITICAL

        Args:
            probability: Risk probability between 0.0 and 1.0.

        Returns:
            The corresponding risk level.
        """
        if probability < 0.25:
            return cls.LOW
        if probability < 0.50:
            return cls.MEDIUM
        if probability < 0.75:
            return cls.HIGH
        return cls.CRITICAL


@dataclass
class RiskSignal:
    """A single risk signal detected in audit data.

    Attributes:
        signal_type: The type of risk signal.
        value: Signal strength between 0.0 and 1.0.
        description: Human-readable explanation.
    """

    signal_type: SignalType
    value: float
    description: str | None = None

    def __post_init__(self) -> None:
        """Clamp value to [0.0, 1.0]."""
        self.value = max(0.0, min(1.0, self.value))


@dataclass
class RiskScore:
    """Aggregate risk score for a conversation.

    Attributes:
        probability: Overall drift probability (0.0 to 1.0).
        level: Classified risk level.
        signals: Individual risk signals that contributed.
    """

    probability: float
    level: RiskLevel
    signals: list[RiskSignal] = field(default_factory=list)

    def to_metadata(self) -> dict[str, str]:
        """Serialize to audit-entry-compatible metadata.

        Returns:
            Dictionary with string keys and values suitable for
            inclusion in ``AuditEntry.metadata``.
        """
        signal_summaries = [
            {
                "type": s.signal_type.value,
                "value": round(s.value, 3),
                "description": s.description,
            }
            for s in self.signals
        ]
        return {
            "drift_probability": str(round(self.probability, 2)),
            "risk_level": self.level.value,
            "risk_signals": json.dumps(signal_summaries, separators=(",", ":")),
        }


#: Default signal weights.
DEFAULT_WEIGHTS: dict[SignalType, float] = {
    SignalType.HIGH_DENY_RATE: 1.0,
    SignalType.RAPID_ACTION_BURST: 0.6,
    SignalType.SENSITIVE_TARGET_ACCESS: 1.2,
    SignalType.ERROR_RATE: 0.5,
    SignalType.REPEATED_DENIALS: 1.0,
    SignalType.ESCALATION_PATTERN: 1.5,
}


class ConversationRiskScorer:
    """Heuristic risk scorer for agent conversations.

    Analyzes audit entries to compute a drift probability —
    a float between 0.0 and 1.0 indicating how likely the
    agent's behavior has deviated from expected patterns.

    Args:
        weights: Custom signal weights. Merged with defaults.
        sensitive_patterns: Additional sensitive path patterns.
        burst_threshold: Minimum actions per second to trigger
            rapid-burst signal. Default: 10.
        deny_rate_threshold: Deny rate above which the signal
            activates. Default: 0.3 (30%).
        repeat_threshold: Minimum repeated denials on the same
            target to trigger the signal. Default: 3.
    """

    def __init__(
        self,
        weights: dict[SignalType, float] | None = None,
        sensitive_patterns: list[str] | None = None,
        burst_threshold: int = 10,
        deny_rate_threshold: float = 0.3,
        repeat_threshold: int = 3,
    ) -> None:
        self._weights = dict(DEFAULT_WEIGHTS)
        if weights:
            self._weights.update(weights)

        self._sensitive_patterns = list(DEFAULT_SENSITIVE_PATTERNS)
        if sensitive_patterns:
            self._sensitive_patterns.extend(sensitive_patterns)

        self._burst_threshold = burst_threshold
        self._deny_rate_threshold = deny_rate_threshold
        self._repeat_threshold = repeat_threshold

    def score(self, entries: list[AuditEntry]) -> RiskScore:
        """Score a sequence of audit entries.

        Args:
            entries: The audit entries to analyze.

        Returns:
            A RiskScore with probability, level, and signals.
        """
        if not entries:
            return RiskScore(
                probability=0.0,
                level=RiskLevel.LOW,
                signals=[],
            )

        signals: list[RiskSignal] = []

        # Compute individual signals
        self._check_deny_rate(entries, signals)
        self._check_error_rate(entries, signals)
        self._check_repeated_denials(entries, signals)
        self._check_sensitive_targets(entries, signals)
        self._check_rapid_burst(entries, signals)
        self._check_escalation(entries, signals)

        # Aggregate weighted signals
        probability = self._aggregate(signals)
        level = RiskLevel.from_probability(probability)

        return RiskScore(
            probability=round(probability, 4),
            level=level,
            signals=signals,
        )

    def _check_deny_rate(
        self,
        entries: list[AuditEntry],
        signals: list[RiskSignal],
    ) -> None:
        """Check for high deny rate."""
        total = len(entries)
        denied = sum(1 for e in entries if e.result == "denied")
        rate = denied / total

        if rate >= self._deny_rate_threshold:
            signals.append(
                RiskSignal(
                    signal_type=SignalType.HIGH_DENY_RATE,
                    value=rate,
                    description=f"{denied}/{total} actions denied ({rate:.0%})",
                )
            )

    def _check_error_rate(
        self,
        entries: list[AuditEntry],
        signals: list[RiskSignal],
    ) -> None:
        """Check for high error rate."""
        total = len(entries)
        errors = sum(1 for e in entries if e.result == "error")
        rate = errors / total

        if rate > 0.1:
            signals.append(
                RiskSignal(
                    signal_type=SignalType.ERROR_RATE,
                    value=rate,
                    description=f"{errors}/{total} actions errored ({rate:.0%})",
                )
            )

    def _check_repeated_denials(
        self,
        entries: list[AuditEntry],
        signals: list[RiskSignal],
    ) -> None:
        """Check for repeated denials on the same target."""
        denied_targets: Counter[str] = Counter()
        for e in entries:
            if e.result == "denied":
                key = f"{e.action}:{e.target}"
                denied_targets[key] += 1

        max_repeats = denied_targets.most_common(1)[0][1] if denied_targets else 0
        if max_repeats >= self._repeat_threshold:
            # Normalize: 3 repeats = 0.5, 10+ repeats = 1.0
            value = min(1.0, (max_repeats - self._repeat_threshold + 1) / 6)
            value = max(value, 0.5)
            target_key = denied_targets.most_common(1)[0][0]
            signals.append(
                RiskSignal(
                    signal_type=SignalType.REPEATED_DENIALS,
                    value=value,
                    description=(f"{max_repeats} repeated denials on {target_key}"),
                )
            )

    def _check_sensitive_targets(
        self,
        entries: list[AuditEntry],
        signals: list[RiskSignal],
    ) -> None:
        """Check for access to sensitive paths/targets."""
        sensitive_hits = 0
        for e in entries:
            target_lower = e.target.lower()
            for pattern in self._sensitive_patterns:
                if pattern.lower() in target_lower:
                    sensitive_hits += 1
                    break

        if sensitive_hits > 0:
            # Normalize: 1 hit = 0.3, 5+ hits = 1.0
            value = min(1.0, 0.3 + (sensitive_hits - 1) * 0.175)
            signals.append(
                RiskSignal(
                    signal_type=SignalType.SENSITIVE_TARGET_ACCESS,
                    value=value,
                    description=(f"{sensitive_hits} sensitive target access attempts"),
                )
            )

    def _check_rapid_burst(
        self,
        entries: list[AuditEntry],
        signals: list[RiskSignal],
    ) -> None:
        """Check for unusually rapid action bursts."""
        if len(entries) < 2:
            return

        timestamps = sorted(e.timestamp for e in entries)
        time_span = (timestamps[-1] - timestamps[0]).total_seconds()

        if time_span == 0:
            # All actions at the same timestamp
            if len(entries) >= self._burst_threshold:
                signals.append(
                    RiskSignal(
                        signal_type=SignalType.RAPID_ACTION_BURST,
                        value=1.0,
                        description=(f"{len(entries)} actions at the same timestamp"),
                    )
                )
            return

        rate = len(entries) / time_span
        if rate >= self._burst_threshold:
            # Normalize: threshold = 0.3, 3x threshold = 1.0
            value = min(1.0, 0.3 + (rate / self._burst_threshold - 1) * 0.35)
            signals.append(
                RiskSignal(
                    signal_type=SignalType.RAPID_ACTION_BURST,
                    value=value,
                    description=(
                        f"{rate:.1f} actions/sec (threshold: {self._burst_threshold})"
                    ),
                )
            )

    def _check_escalation(
        self,
        entries: list[AuditEntry],
        signals: list[RiskSignal],
    ) -> None:
        """Check for escalation pattern in denial severity."""
        severities: list[int] = []
        for e in entries:
            if e.result == "denied" and e.metadata:
                sev = e.metadata.get("severity", "")
                if sev in _SEVERITY_ORDER:
                    severities.append(_SEVERITY_ORDER[sev])

        if len(severities) < 2:
            return

        # Count consecutive increases
        increases = 0
        for i in range(1, len(severities)):
            if severities[i] > severities[i - 1]:
                increases += 1

        if increases > 0:
            # Normalize: 1 increase = 0.3, 3+ increases = 1.0
            value = min(1.0, 0.3 + (increases - 1) * 0.35)
            signals.append(
                RiskSignal(
                    signal_type=SignalType.ESCALATION_PATTERN,
                    value=value,
                    description=(f"{increases} severity escalation(s) detected"),
                )
            )

    def _aggregate(self, signals: list[RiskSignal]) -> float:
        """Aggregate weighted signals into a single probability.

        Uses a weighted combination clamped to [0.0, 1.0].

        Args:
            signals: The risk signals to aggregate.

        Returns:
            Probability between 0.0 and 1.0.
        """
        if not signals:
            return 0.0

        weighted_sum = sum(
            s.value * self._weights.get(s.signal_type, 1.0) for s in signals
        )

        # Normalize by the sum of ALL possible weights to avoid
        # saturation when only a few signals fire.
        max_possible_weight = sum(self._weights.values())
        if max_possible_weight == 0:
            return 0.0

        probability = weighted_sum / max_possible_weight
        return max(0.0, min(1.0, probability))
