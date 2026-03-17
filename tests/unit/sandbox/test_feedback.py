"""Tests for feedback loop detection.

The feedback loop detector simulates multi-turn conversations where
denial messages from the Guard get re-injected as subsequent LLM
requests, detecting context poisoning patterns.
"""

from __future__ import annotations

from agentguard.policies.guard import Guard


class TestFeedbackLoopResult:
    """Tests for the FeedbackLoopResult data model."""

    def test_no_loop_result(self) -> None:
        from agentguard.sandbox.feedback import FeedbackLoopResult

        result = FeedbackLoopResult(
            scenario_name="test",
            turns=3,
            denials_per_turn=[0, 0, 0],
            max_consecutive_denials=0,
            has_feedback_loop=False,
        )
        assert result.has_feedback_loop is False
        assert result.max_consecutive_denials == 0

    def test_loop_detected(self) -> None:
        from agentguard.sandbox.feedback import FeedbackLoopResult

        result = FeedbackLoopResult(
            scenario_name="poison",
            turns=5,
            denials_per_turn=[0, 1, 1, 1, 1],
            max_consecutive_denials=4,
            has_feedback_loop=True,
        )
        assert result.has_feedback_loop is True
        assert result.max_consecutive_denials == 4


class TestSimulateConversation:
    """Tests for the simulate_conversation() function.

    This function takes an initial prompt, sends it through the Guard,
    and if denied, constructs the next turn as:
      "[LLM error message] + original prompt context"
    This simulates how an LLM agent would retry after getting a denial.
    """

    def test_no_denials_no_loop(self) -> None:
        """A benign prompt should produce no denials over multiple turns."""
        from agentguard.sandbox.feedback import simulate_conversation

        guard = Guard()
        guard.load_policy_file(
            "src/agentguard/policies/builtin_policies/no-secret-in-prompt.yaml"
        )

        result = simulate_conversation(
            scenario_name="benign",
            initial_prompt="How do I implement password hashing?",
            guard=guard,
            max_turns=5,
        )
        assert result.has_feedback_loop is False
        assert result.max_consecutive_denials == 0

    def test_denial_of_narrow_pattern_still_loops_due_to_context(self) -> None:
        """Even a narrow pattern creates a loop because the original prompt
        stays in the conversation context on retries.

        This is realistic: agents keep the original task in context when
        retrying, so the triggering content is always present.
        """
        from agentguard.sandbox.feedback import simulate_conversation

        guard = Guard()
        guard.load_policy_string("""
name: narrow-block
rules:
  - action: llm_request
    deny:
      - pattern: 'EVIL_PATTERN_XYZ'
    severity: high
    scan: messages
""")
        result = simulate_conversation(
            scenario_name="narrow-but-loops",
            initial_prompt="Please use EVIL_PATTERN_XYZ in the code",
            guard=guard,
            max_turns=5,
        )
        # Every turn is denied because the original prompt content
        # ("EVIL_PATTERN_XYZ") is preserved in the retry context
        assert result.denials_per_turn[0] == 1
        assert result.has_feedback_loop is True
        assert result.max_consecutive_denials == 5

    def test_detects_feedback_loop_with_broad_pattern(self) -> None:
        """A broad pattern like 'Bearer' can create a feedback loop.

        1. User mentions Bearer → denied
        2. Denial msg "Blocked by policy: ... Bearer" → contains 'Bearer' → denied again
        3. Repeat forever
        """
        from agentguard.sandbox.feedback import simulate_conversation

        guard = Guard()
        guard.load_policy_string("""
name: overly-broad
rules:
  - action: llm_request
    deny:
      - pattern: 'Bearer'
    severity: high
    scan: messages
""")
        result = simulate_conversation(
            scenario_name="bearer-loop",
            initial_prompt="How does Bearer authentication work?",
            guard=guard,
            max_turns=5,
        )
        # The denial message itself contains "Bearer" (from the policy name
        # or the matched pattern), so it re-triggers on every turn
        assert result.has_feedback_loop is True
        assert result.max_consecutive_denials >= 3

    def test_max_turns_limits_simulation(self) -> None:
        """Simulation stops after max_turns even in a loop."""
        from agentguard.sandbox.feedback import simulate_conversation

        guard = Guard()
        guard.load_policy_string("""
name: always-deny
rules:
  - action: llm_request
    deny:
      - pattern: '.'
    severity: high
    scan: messages
""")
        result = simulate_conversation(
            scenario_name="infinite",
            initial_prompt="anything",
            guard=guard,
            max_turns=3,
        )
        assert result.turns == 3
        assert len(result.denials_per_turn) == 3


class TestFeedbackLoopDetector:
    """Tests for running feedback loop detection across multiple prompts."""

    def test_check_prompts_returns_results(self) -> None:
        from agentguard.sandbox.feedback import check_feedback_loops

        guard = Guard()
        prompts = {
            "benign": "How do I write Python tests?",
            "auth-docs": "Explain OAuth2 Bearer token flow",
        }
        results = check_feedback_loops(prompts, guard, max_turns=3)
        assert len(results) == 2
        assert "benign" in results
        assert "auth-docs" in results

    def test_returns_empty_for_empty_prompts(self) -> None:
        from agentguard.sandbox.feedback import check_feedback_loops

        results = check_feedback_loops({}, Guard(), max_turns=3)
        assert results == {}

    def test_detects_loop_in_mixed_set(self) -> None:
        """Among mixed prompts, only the problematic one should show a loop."""
        from agentguard.sandbox.feedback import check_feedback_loops

        guard = Guard()
        guard.load_policy_string("""
name: broad-password
rules:
  - action: llm_request
    deny:
      - pattern: '(?i)password'
    severity: high
    scan: messages
""")
        prompts = {
            "safe": "How do I sort a list in Python?",
            "triggers-loop": "How do I validate a password field?",
        }
        results = check_feedback_loops(prompts, guard, max_turns=5)
        assert results["safe"].has_feedback_loop is False
        # The word "password" appears in the prompt AND would appear in
        # the denial message about "password", creating a loop
        assert results["triggers-loop"].has_feedback_loop is True
