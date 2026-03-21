"""Tests for conversation risk scoring (M14).

Covers:
- RiskSignal creation and types
- RiskScore computation
- Individual heuristic signals
- Aggregate scoring from audit entries
- ConversationRiskScorer with configurable weights
- Metadata enrichment of audit entries
- Severity classification from risk scores
"""

from __future__ import annotations

from datetime import datetime, timezone

from agentguard.audit.models import AuditEntry
from agentguard.audit.risk import (
    ConversationRiskScorer,
    RiskLevel,
    RiskScore,
    RiskSignal,
    SignalType,
)

# --- RiskSignal ---


class TestRiskSignal:
    """Tests for RiskSignal dataclass."""

    def test_create_signal(self) -> None:
        signal = RiskSignal(
            signal_type=SignalType.HIGH_DENY_RATE,
            value=0.8,
            description="80% of actions denied",
        )
        assert signal.signal_type == SignalType.HIGH_DENY_RATE
        assert signal.value == 0.8
        assert signal.description == "80% of actions denied"

    def test_signal_value_clamped_0_to_1(self) -> None:
        signal = RiskSignal(
            signal_type=SignalType.HIGH_DENY_RATE,
            value=1.5,
        )
        assert signal.value == 1.0

        signal2 = RiskSignal(
            signal_type=SignalType.HIGH_DENY_RATE,
            value=-0.5,
        )
        assert signal2.value == 0.0


# --- SignalType ---


class TestSignalType:
    """Tests for signal type enum."""

    def test_signal_types_exist(self) -> None:
        assert SignalType.HIGH_DENY_RATE.value == "high_deny_rate"
        assert SignalType.RAPID_ACTION_BURST.value == "rapid_action_burst"
        assert SignalType.SENSITIVE_TARGET_ACCESS.value == "sensitive_target_access"
        assert SignalType.ERROR_RATE.value == "error_rate"
        assert SignalType.REPEATED_DENIALS.value == "repeated_denials"
        assert SignalType.ESCALATION_PATTERN.value == "escalation_pattern"


# --- RiskScore ---


class TestRiskScore:
    """Tests for RiskScore dataclass."""

    def test_create_risk_score(self) -> None:
        score = RiskScore(
            probability=0.75,
            level=RiskLevel.HIGH,
            signals=[
                RiskSignal(
                    signal_type=SignalType.HIGH_DENY_RATE,
                    value=0.8,
                ),
            ],
        )
        assert score.probability == 0.75
        assert score.level == RiskLevel.HIGH
        assert len(score.signals) == 1

    def test_risk_score_to_metadata(self) -> None:
        """Risk score should serialize to audit-compatible metadata."""
        score = RiskScore(
            probability=0.73,
            level=RiskLevel.HIGH,
            signals=[
                RiskSignal(
                    signal_type=SignalType.HIGH_DENY_RATE,
                    value=0.8,
                    description="80% denied",
                ),
            ],
        )
        meta = score.to_metadata()
        assert meta["drift_probability"] == "0.73"
        assert meta["risk_level"] == "high"
        assert "high_deny_rate" in meta["risk_signals"]


# --- RiskLevel ---


class TestRiskLevel:
    """Tests for RiskLevel enum."""

    def test_risk_levels(self) -> None:
        assert RiskLevel.LOW.value == "low"
        assert RiskLevel.MEDIUM.value == "medium"
        assert RiskLevel.HIGH.value == "high"
        assert RiskLevel.CRITICAL.value == "critical"

    def test_from_probability(self) -> None:
        assert RiskLevel.from_probability(0.1) == RiskLevel.LOW
        assert RiskLevel.from_probability(0.35) == RiskLevel.MEDIUM
        assert RiskLevel.from_probability(0.65) == RiskLevel.HIGH
        assert RiskLevel.from_probability(0.85) == RiskLevel.CRITICAL

    def test_from_probability_boundaries(self) -> None:
        assert RiskLevel.from_probability(0.0) == RiskLevel.LOW
        assert RiskLevel.from_probability(0.25) == RiskLevel.MEDIUM
        assert RiskLevel.from_probability(0.5) == RiskLevel.HIGH
        assert RiskLevel.from_probability(0.75) == RiskLevel.CRITICAL
        assert RiskLevel.from_probability(1.0) == RiskLevel.CRITICAL


# --- ConversationRiskScorer ---


class TestConversationRiskScorer:
    """Tests for the main risk scoring engine."""

    def _make_entry(
        self,
        action: str = "shell_execute",
        actor: str = "agent",
        target: str = "ls",
        result: str = "allowed",
        metadata: dict[str, str] | None = None,
        timestamp: datetime | None = None,
    ) -> AuditEntry:
        return AuditEntry(
            action=action,
            actor=actor,
            target=target,
            result=result,
            metadata=metadata,
            timestamp=timestamp or datetime.now(tz=timezone.utc),
        )

    def test_empty_entries_low_risk(self) -> None:
        scorer = ConversationRiskScorer()
        score = scorer.score([])
        assert score.probability == 0.0
        assert score.level == RiskLevel.LOW

    def test_all_allowed_low_risk(self) -> None:
        scorer = ConversationRiskScorer()
        entries = [self._make_entry(result="allowed") for _ in range(10)]
        score = scorer.score(entries)
        assert score.probability < 0.25
        assert score.level == RiskLevel.LOW

    def test_high_deny_rate_signal(self) -> None:
        scorer = ConversationRiskScorer()
        entries = [self._make_entry(result="denied") for _ in range(8)] + [
            self._make_entry(result="allowed") for _ in range(2)
        ]
        score = scorer.score(entries)
        # 80% deny rate should produce high risk
        deny_signals = [
            s for s in score.signals if s.signal_type == SignalType.HIGH_DENY_RATE
        ]
        assert len(deny_signals) == 1
        assert deny_signals[0].value > 0.5

    def test_error_rate_signal(self) -> None:
        scorer = ConversationRiskScorer()
        entries = [self._make_entry(result="error") for _ in range(5)] + [
            self._make_entry(result="allowed") for _ in range(5)
        ]
        score = scorer.score(entries)
        error_signals = [
            s for s in score.signals if s.signal_type == SignalType.ERROR_RATE
        ]
        assert len(error_signals) == 1
        assert error_signals[0].value > 0.0

    def test_repeated_denials_same_target(self) -> None:
        scorer = ConversationRiskScorer()
        entries = [
            self._make_entry(
                action="file_write",
                target="/etc/passwd",
                result="denied",
            )
            for _ in range(5)
        ]
        score = scorer.score(entries)
        repeat_signals = [
            s for s in score.signals if s.signal_type == SignalType.REPEATED_DENIALS
        ]
        assert len(repeat_signals) == 1
        assert repeat_signals[0].value >= 0.5

    def test_sensitive_target_access(self) -> None:
        scorer = ConversationRiskScorer()
        entries = [
            self._make_entry(
                action="file_read",
                target="/etc/shadow",
                result="denied",
            ),
            self._make_entry(
                action="file_read",
                target="/.env",
                result="denied",
            ),
            self._make_entry(
                action="file_read",
                target="/home/user/.ssh/id_rsa",
                result="denied",
            ),
        ]
        score = scorer.score(entries)
        sensitive_signals = [
            s
            for s in score.signals
            if s.signal_type == SignalType.SENSITIVE_TARGET_ACCESS
        ]
        assert len(sensitive_signals) == 1
        assert sensitive_signals[0].value > 0.0

    def test_rapid_action_burst(self) -> None:
        scorer = ConversationRiskScorer()
        base = datetime(2026, 3, 21, 12, 0, 0, tzinfo=timezone.utc)
        # 20 actions in 1 second
        entries = [
            self._make_entry(
                timestamp=base,
                result="allowed",
            )
            for _ in range(20)
        ]
        score = scorer.score(entries)
        burst_signals = [
            s for s in score.signals if s.signal_type == SignalType.RAPID_ACTION_BURST
        ]
        assert len(burst_signals) == 1
        assert burst_signals[0].value > 0.0

    def test_escalation_pattern(self) -> None:
        """Escalation: allowed -> denied -> denied with higher severity."""
        scorer = ConversationRiskScorer()
        entries = [
            self._make_entry(result="allowed"),
            self._make_entry(result="denied", metadata={"severity": "low"}),
            self._make_entry(result="denied", metadata={"severity": "medium"}),
            self._make_entry(result="denied", metadata={"severity": "high"}),
            self._make_entry(result="denied", metadata={"severity": "critical"}),
        ]
        score = scorer.score(entries)
        esc_signals = [
            s for s in score.signals if s.signal_type == SignalType.ESCALATION_PATTERN
        ]
        assert len(esc_signals) == 1
        assert esc_signals[0].value > 0.0

    def test_combined_signals_increase_risk(self) -> None:
        """Multiple risk signals should combine to increase overall score."""
        scorer = ConversationRiskScorer()
        # High deny rate + sensitive targets + repeated denials
        entries = [
            self._make_entry(
                action="file_write",
                target="/etc/passwd",
                result="denied",
                metadata={"severity": "critical"},
            )
            for _ in range(10)
        ]
        score = scorer.score(entries)
        assert score.probability >= 0.5
        assert score.level in (RiskLevel.HIGH, RiskLevel.CRITICAL)

    def test_custom_weights(self) -> None:
        scorer = ConversationRiskScorer(
            weights={SignalType.HIGH_DENY_RATE: 2.0},
        )
        entries = [self._make_entry(result="denied") for _ in range(8)] + [
            self._make_entry(result="allowed") for _ in range(2)
        ]
        score_weighted = scorer.score(entries)

        scorer_default = ConversationRiskScorer()
        score_default = scorer_default.score(entries)

        # Higher weight should produce higher probability
        assert score_weighted.probability >= score_default.probability

    def test_custom_sensitive_patterns(self) -> None:
        scorer = ConversationRiskScorer(
            sensitive_patterns=["/secret/"],
        )
        entries = [
            self._make_entry(
                action="file_read",
                target="/secret/keys.txt",
                result="denied",
            ),
        ]
        score = scorer.score(entries)
        sensitive_signals = [
            s
            for s in score.signals
            if s.signal_type == SignalType.SENSITIVE_TARGET_ACCESS
        ]
        assert len(sensitive_signals) == 1
