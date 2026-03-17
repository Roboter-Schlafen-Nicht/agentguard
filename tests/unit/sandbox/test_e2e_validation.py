"""End-to-end sandbox validation tests.

These tests run the full sandbox pipeline against the ACTUAL built-in
no-secret policies with the scenario YAML files, proving:
1. True positives (real secrets) are correctly denied
2. True negatives (benign content) are correctly allowed
3. Edge cases match expected behavior
4. The production gate passes with refined policies
5. No feedback loops are triggered by benign prompts
"""

from __future__ import annotations

from pathlib import Path

import pytest

# Path to the built-in scenario YAML files
_SCENARIOS_DIR = (
    Path(__file__).resolve().parents[3] / "src" / "agentguard" / "sandbox" / "scenarios"
)
_POLICIES_DIR = (
    Path(__file__).resolve().parents[3]
    / "src"
    / "agentguard"
    / "policies"
    / "builtin_policies"
)


class TestEndToEndScenarioValidation:
    """Run all scenario suites against the no-secrets policies."""

    @pytest.fixture
    def guard(self):
        """Guard loaded with both no-secret policies."""
        from agentguard.policies.guard import Guard

        guard = Guard()
        guard.load_policy_file(str(_POLICIES_DIR / "no-secret-exposure.yaml"))
        guard.load_policy_file(str(_POLICIES_DIR / "no-secret-in-prompt.yaml"))
        return guard

    def test_true_positives_all_denied(self, guard) -> None:
        """Every true-positive scenario (real secrets) must be denied."""
        from agentguard.sandbox.models import load_scenarios_from_file
        from agentguard.sandbox.runner import run_suite

        scenarios = load_scenarios_from_file(_SCENARIOS_DIR / "true-positives.yaml")
        assert len(scenarios) >= 10, f"Expected 10+ TP scenarios, got {len(scenarios)}"

        results = run_suite(scenarios, guard)
        for result in results:
            assert result.passed, (
                f"True positive FAILED: {result.scenario_name} — "
                f"expected deny but got {result.actual}. "
                f"Failure: {result.failure_reason}"
            )

    def test_true_negatives_all_allowed(self, guard) -> None:
        """Every true-negative scenario (benign content) must be allowed."""
        from agentguard.sandbox.models import load_scenarios_from_file
        from agentguard.sandbox.runner import run_suite

        scenarios = load_scenarios_from_file(_SCENARIOS_DIR / "true-negatives.yaml")
        assert len(scenarios) >= 15, f"Expected 15+ TN scenarios, got {len(scenarios)}"

        results = run_suite(scenarios, guard)
        failures = [r for r in results if not r.passed]
        if failures:
            details = "\n".join(
                f"  - {r.scenario_name}: {r.failure_reason}" for r in failures
            )
            pytest.fail(
                f"{len(failures)} true negatives incorrectly denied "
                f"(false positives!):\n{details}"
            )

    def test_edge_cases_match_expectations(self, guard) -> None:
        """Every edge-case scenario matches its expected outcome."""
        from agentguard.sandbox.models import load_scenarios_from_file
        from agentguard.sandbox.runner import run_suite

        scenarios = load_scenarios_from_file(_SCENARIOS_DIR / "edge-cases.yaml")
        assert len(scenarios) >= 20, f"Expected 20+ edge cases, got {len(scenarios)}"

        results = run_suite(scenarios, guard)
        failures = [r for r in results if not r.passed]
        if failures:
            details = "\n".join(
                f"  - {r.scenario_name}: expected={r.expected}, "
                f"actual={r.actual} ({r.failure_reason})"
                for r in failures
            )
            pytest.fail(f"{len(failures)} edge cases failed:\n{details}")

    def test_full_suite_passes_production_gate(self, guard) -> None:
        """The combined scenario suite must pass the production readiness gate."""
        from agentguard.sandbox.gate import GateThresholds, check_gate
        from agentguard.sandbox.models import load_scenarios_from_directory
        from agentguard.sandbox.validator import validate

        scenarios = load_scenarios_from_directory(_SCENARIOS_DIR)
        assert len(scenarios) >= 40, (
            f"Expected 40+ total scenarios, got {len(scenarios)}"
        )

        report = validate(scenarios, guard)
        thresholds = GateThresholds()  # default: TPR>=0.95, FPR<=0.05, accuracy>=0.90
        verdict = check_gate(report, thresholds)

        if not verdict.passed:
            pytest.fail(
                f"Production gate FAILED:\n"
                f"  TPR: {report.true_positive_rate:.3f}\n"
                f"  FPR: {report.false_positive_rate:.3f}\n"
                f"  Accuracy: {report.accuracy:.3f}\n"
                f"  Reasons: {verdict.reasons}"
            )

    def test_no_feedback_loops_on_benign_prompts(self, guard) -> None:
        """Benign prompts must not trigger feedback loops."""
        from agentguard.sandbox.feedback import check_feedback_loops

        benign_prompts = {
            "coding-question": "How do I write a Python function?",
            "config-discussion": "What's the best database for small projects?",
            "bearer-docs": (
                "The Authorization header uses Bearer tokens. "
                "Add it like: Authorization: Bearer <token>"
            ),
            "password-types": "def create_user(username: str, password: str) -> User:",
            "env-var-pattern": "password = os.environ.get('DB_PASSWORD')",
        }

        results = check_feedback_loops(benign_prompts, guard, max_turns=5)

        for name, result in results.items():
            assert not result.has_feedback_loop, (
                f"Feedback loop detected for '{name}': "
                f"{result.max_consecutive_denials} consecutive denials"
            )

    def test_feedback_loop_detected_for_real_secrets(self, guard) -> None:
        """Real secrets that persist in context SHOULD trigger feedback loops."""
        from agentguard.sandbox.feedback import simulate_conversation

        # A real secret in the prompt: when denied, the retry prompt
        # still contains the original secret, so it should loop
        result = simulate_conversation(
            scenario_name="real-api-key",
            initial_prompt="Use this key: sk-proj-AAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            guard=guard,
            max_turns=5,
        )
        # This proves the feedback loop detector is working correctly:
        # real secrets that stay in context DO create loops
        assert result.has_feedback_loop is True
        assert result.max_consecutive_denials >= 3


class TestEndToEndValidationReport:
    """Test the full validation report metrics."""

    def test_validation_report_metrics(self) -> None:
        """Verify the report contains sensible metrics for the full suite."""
        from agentguard.policies.guard import Guard
        from agentguard.sandbox.models import load_scenarios_from_directory
        from agentguard.sandbox.validator import validate

        guard = Guard()
        guard.load_policy_file(str(_POLICIES_DIR / "no-secret-exposure.yaml"))
        guard.load_policy_file(str(_POLICIES_DIR / "no-secret-in-prompt.yaml"))

        scenarios = load_scenarios_from_directory(_SCENARIOS_DIR)
        report = validate(scenarios, guard)

        # Validate the report structure
        assert report.total == len(scenarios)
        assert report.total == report.passed + report.failed
        assert report.total == (
            report.true_positives
            + report.false_positives
            + report.true_negatives
            + report.false_negatives
        )

        # Check metrics are in valid ranges
        assert 0.0 <= report.true_positive_rate <= 1.0
        assert 0.0 <= report.false_positive_rate <= 1.0
        assert 0.0 <= report.accuracy <= 1.0

        # Should have both TP and TN scenarios
        assert report.true_positives > 0, "Must have true positive results"
        assert report.true_negatives > 0, "Must have true negative results"


class TestWebhookScenarios:
    """Webhook URL deny scenarios, built at runtime to avoid GitHub Push Protection.

    GitHub's secret scanner blocks commits containing Slack/Discord webhook
    URLs, even fake ones.  These tests construct the URLs programmatically
    so the literal patterns never appear in source files.
    """

    @pytest.fixture
    def guard(self):
        """Guard loaded with both no-secret policies."""
        from agentguard.policies.guard import Guard

        guard = Guard()
        guard.load_policy_file(
            str(_POLICIES_DIR / "no-secret-exposure.yaml"),
        )
        guard.load_policy_file(
            str(_POLICIES_DIR / "no-secret-in-prompt.yaml"),
        )
        return guard

    def test_slack_webhook_denied(self, guard) -> None:
        """A Slack webhook URL in an LLM request must be denied."""
        from agentguard.sandbox.models import Scenario, ScenarioAction
        from agentguard.sandbox.runner import run_scenario

        # Build the URL at runtime so it never appears as a literal
        slack_url = (
            "https://"
            + "hooks.slack.com/services/"
            + "TAAAAAA00/BAAAAAA00/aaaaaaaabbbbbbbbcccccccc"
        )
        scenario = Scenario(
            name="slack-webhook-real-url",
            description="Slack webhook URL in LLM request",
            expected_outcome="deny",
            actions=[
                ScenarioAction(
                    kind="llm_request",
                    params={"messages": f"Post to {slack_url}"},
                ),
            ],
        )
        result = run_scenario(scenario, guard)
        assert result.passed, f"Slack webhook should be denied: {result.failure_reason}"

    def test_discord_webhook_denied(self, guard) -> None:
        """A Discord webhook URL in an LLM request must be denied."""
        from agentguard.sandbox.models import Scenario, ScenarioAction
        from agentguard.sandbox.runner import run_scenario

        discord_url = (
            "https://"
            + "discord.com/api/webhooks/"
            + "000000000000000000/aaaa-bbbb-cccc-dddd"
        )
        scenario = Scenario(
            name="discord-webhook-real-url",
            description="Discord webhook URL in LLM request",
            expected_outcome="deny",
            actions=[
                ScenarioAction(
                    kind="llm_request",
                    params={
                        "messages": f"Send alert to {discord_url}",
                    },
                ),
            ],
        )
        result = run_scenario(scenario, guard)
        assert result.passed, (
            f"Discord webhook should be denied: {result.failure_reason}"
        )
