"""Tests for the inbound scanner — streaming-aware response scanning.

The inbound scanner accumulates LLM response content as it streams
through the proxy and runs Guard policies incrementally against the
accumulated window.  When a policy violation is detected mid-stream,
the scanner signals denial so the proxy can terminate the stream early.
"""

from __future__ import annotations

import re

from agentguard.policies.guard import Guard
from agentguard.policies.models import Policy, Rule
from agentguard.proxy.inbound import InboundScanner, ScanResult


def _make_guard_with_deny(pattern: str, policy_name: str = "test-policy") -> Guard:
    """Create a Guard with a single llm_response deny rule."""
    rule = Rule(
        action_kind="llm_response",
        deny_patterns=[re.compile(pattern)],
        severity="high",
        description="Test deny rule",
    )
    policy = Policy(name=policy_name, rules=[rule], description="Test policy")
    guard = Guard()
    guard.add_policy(policy)
    return guard


# ===========================================================================
# Test: ScanResult dataclass
# ===========================================================================


class TestScanResult:
    """Test ScanResult fields and defaults."""

    def test_scan_result_fields(self) -> None:
        result = ScanResult(
            denied=True,
            denied_by="test-policy",
            reason="matched pattern",
            scanned_length=42,
            token_estimate=10,
        )
        assert result.denied is True
        assert result.denied_by == "test-policy"
        assert result.reason == "matched pattern"
        assert result.scanned_length == 42
        assert result.token_estimate == 10

    def test_scan_result_allowed(self) -> None:
        result = ScanResult(
            denied=False,
            denied_by=None,
            reason=None,
            scanned_length=100,
            token_estimate=25,
        )
        assert result.denied is False
        assert result.denied_by is None
        assert result.reason is None


# ===========================================================================
# Test: InboundScanner.feed() — basic behavior
# ===========================================================================


class TestInboundScannerFeed:
    """Test feeding content to the inbound scanner."""

    def test_feed_benign_content_returns_none(self) -> None:
        """Benign content should not trigger denial."""
        guard = _make_guard_with_deny(r"HARMFUL_CONTENT")
        scanner = InboundScanner(guard)

        result = scanner.feed("Hello, how are you?")
        assert result is None

    def test_feed_harmful_content_returns_scan_result(self) -> None:
        """Harmful content matching a policy should return denial."""
        guard = _make_guard_with_deny(r"HARMFUL_CONTENT")
        scanner = InboundScanner(guard)

        result = scanner.feed("This contains HARMFUL_CONTENT here")
        assert result is not None
        assert result.denied is True
        assert result.denied_by == "test-policy"

    def test_feed_accumulates_content(self) -> None:
        """Multiple feeds should accumulate content."""
        guard = _make_guard_with_deny(r"HARMFUL_CONTENT")
        scanner = InboundScanner(guard)

        scanner.feed("Hello ")
        scanner.feed("world ")
        assert scanner.accumulated_content == "Hello world "

    def test_feed_detects_pattern_across_chunks(self) -> None:
        """Pattern spanning two chunks should be detected."""
        guard = _make_guard_with_deny(r"HARMFUL_CONTENT")
        scanner = InboundScanner(guard)

        # Feed partial pattern
        result1 = scanner.feed("This has HARMFUL")
        assert result1 is None  # Not yet a match

        # Complete the pattern
        result2 = scanner.feed("_CONTENT in it")
        assert result2 is not None
        assert result2.denied is True

    def test_feed_empty_string_no_error(self) -> None:
        """Feeding empty string should not error or trigger."""
        guard = _make_guard_with_deny(r"HARMFUL_CONTENT")
        scanner = InboundScanner(guard)

        result = scanner.feed("")
        assert result is None

    def test_feed_after_denial_raises_or_returns_denied(self) -> None:
        """Feeding after denial should still show denied state."""
        guard = _make_guard_with_deny(r"HARMFUL")
        scanner = InboundScanner(guard)

        result1 = scanner.feed("HARMFUL")
        assert result1 is not None
        assert result1.denied is True

        # Scanner is already in denied state
        result2 = scanner.feed("more content")
        assert result2 is not None
        assert result2.denied is True


# ===========================================================================
# Test: InboundScanner.finalize() — end-of-stream summary
# ===========================================================================


class TestInboundScannerFinalize:
    """Test finalize() end-of-stream behavior."""

    def test_finalize_clean_stream(self) -> None:
        """Finalize on clean stream should return allowed result."""
        guard = _make_guard_with_deny(r"HARMFUL")
        scanner = InboundScanner(guard)

        scanner.feed("Hello ")
        scanner.feed("world!")
        result = scanner.finalize()

        assert result.denied is False
        assert result.denied_by is None
        assert result.scanned_length == len("Hello world!")
        assert result.token_estimate > 0

    def test_finalize_after_denial(self) -> None:
        """Finalize after denial should return denied result."""
        guard = _make_guard_with_deny(r"HARMFUL")
        scanner = InboundScanner(guard)

        scanner.feed("HARMFUL stuff")
        result = scanner.finalize()

        assert result.denied is True
        assert result.denied_by == "test-policy"
        assert result.scanned_length > 0

    def test_finalize_empty_stream(self) -> None:
        """Finalize with no content should return allowed, zero stats."""
        guard = _make_guard_with_deny(r"HARMFUL")
        scanner = InboundScanner(guard)

        result = scanner.finalize()

        assert result.denied is False
        assert result.scanned_length == 0
        assert result.token_estimate == 0

    def test_finalize_token_estimate_scales(self) -> None:
        """Token estimate should scale with content length."""
        guard = _make_guard_with_deny(r"HARMFUL")
        scanner = InboundScanner(guard)

        short_text = "Hi"
        long_text = "This is a much longer piece of content " * 20
        scanner.feed(short_text)
        short_result = scanner.finalize()

        scanner2 = InboundScanner(guard)
        scanner2.feed(long_text)
        long_result = scanner2.finalize()

        assert long_result.token_estimate > short_result.token_estimate


# ===========================================================================
# Test: InboundScanner with scan target
# ===========================================================================


class TestInboundScannerScanTarget:
    """Test scanning with scan target (content parameter)."""

    def test_uses_content_param_for_check(self) -> None:
        """Scanner should pass accumulated content as 'content' param."""
        # Create a rule that scans the 'content' parameter
        from agentguard.policies.models import ScanTarget

        rule = Rule(
            action_kind="llm_response",
            deny_patterns=[re.compile(r"SECRET_DATA")],
            severity="critical",
            scan=ScanTarget.CONTENT,
        )
        policy = Policy(name="scan-content", rules=[rule])
        guard = Guard()
        guard.add_policy(policy)
        scanner = InboundScanner(guard)

        result = scanner.feed("Contains SECRET_DATA here")
        assert result is not None
        assert result.denied is True

    def test_no_false_positive_with_different_scan_target(self) -> None:
        """Rule scanning 'system' should not match on content."""
        from agentguard.policies.models import ScanTarget

        rule = Rule(
            action_kind="llm_response",
            deny_patterns=[re.compile(r"SECRET_DATA")],
            severity="critical",
            scan=ScanTarget.SYSTEM,
        )
        policy = Policy(name="scan-system", rules=[rule])
        guard = Guard()
        guard.add_policy(policy)
        scanner = InboundScanner(guard)

        # Content has SECRET_DATA but rule scans 'system' param, not 'content'
        result = scanner.feed("Contains SECRET_DATA here")
        assert result is None


# ===========================================================================
# Test: Multiple policies
# ===========================================================================


class TestInboundScannerMultiplePolicies:
    """Test with multiple policies loaded."""

    def test_first_matching_policy_wins(self) -> None:
        """First policy to match should be reported."""
        guard = Guard()
        policy1 = Policy(
            name="policy-a",
            rules=[
                Rule(
                    action_kind="llm_response",
                    deny_patterns=[re.compile(r"PATTERN_A")],
                    severity="high",
                )
            ],
        )
        policy2 = Policy(
            name="policy-b",
            rules=[
                Rule(
                    action_kind="llm_response",
                    deny_patterns=[re.compile(r"PATTERN_B")],
                    severity="high",
                )
            ],
        )
        guard.add_policy(policy1)
        guard.add_policy(policy2)

        scanner = InboundScanner(guard)
        result = scanner.feed("This has PATTERN_B")
        assert result is not None
        assert result.denied is True

    def test_no_match_across_multiple_policies(self) -> None:
        """Content not matching any policy should not trigger."""
        guard = Guard()
        policy1 = Policy(
            name="policy-a",
            rules=[
                Rule(
                    action_kind="llm_response",
                    deny_patterns=[re.compile(r"PATTERN_A")],
                    severity="high",
                )
            ],
        )
        policy2 = Policy(
            name="policy-b",
            rules=[
                Rule(
                    action_kind="llm_response",
                    deny_patterns=[re.compile(r"PATTERN_B")],
                    severity="high",
                )
            ],
        )
        guard.add_policy(policy1)
        guard.add_policy(policy2)

        scanner = InboundScanner(guard)
        result = scanner.feed("Perfectly safe content")
        assert result is None


# ===========================================================================
# Test: accumulated_content property
# ===========================================================================


class TestAccumulatedContent:
    """Test the accumulated_content property."""

    def test_empty_initially(self) -> None:
        guard = _make_guard_with_deny(r"HARMFUL")
        scanner = InboundScanner(guard)
        assert scanner.accumulated_content == ""

    def test_tracks_all_fed_content(self) -> None:
        guard = _make_guard_with_deny(r"HARMFUL")
        scanner = InboundScanner(guard)
        scanner.feed("Hello ")
        scanner.feed("world")
        assert scanner.accumulated_content == "Hello world"
