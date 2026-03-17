"""Tests for the sandbox scenario runner.

The runner takes a list of Scenarios and a Guard, executes each action
through the Guard, and produces ScenarioResults.
"""

from __future__ import annotations

from agentguard.policies.guard import Guard


class TestScenarioRunner:
    """Tests for running scenarios through the Guard."""

    def test_allow_scenario_passes_when_all_actions_allowed(self) -> None:
        """A scenario expecting 'allow' passes when no actions are denied."""
        from agentguard.sandbox.models import Scenario, ScenarioAction
        from agentguard.sandbox.runner import run_scenario

        scenario = Scenario(
            name="benign-read",
            description="Read a normal file",
            expected_outcome="allow",
            actions=[
                ScenarioAction(kind="file_read", params={"path": "/tmp/readme.txt"}),
            ],
        )
        guard = Guard()  # No policies = everything allowed
        result = run_scenario(scenario, guard)
        assert result.passed is True
        assert result.actual == "allow"

    def test_deny_scenario_passes_when_action_denied(self) -> None:
        """A scenario expecting 'deny' passes when at least one action is denied."""
        from agentguard.sandbox.models import Scenario, ScenarioAction
        from agentguard.sandbox.runner import run_scenario

        scenario = Scenario(
            name="secret-exposure",
            description="Write a real API key",
            expected_outcome="deny",
            actions=[
                ScenarioAction(
                    kind="file_write",
                    params={
                        "content": "API_KEY = sk-abcdefghijklmnopqrstuvwxyz1234567890"
                    },
                ),
            ],
        )
        # Load a guard with the no-secret-exposure policy
        guard = Guard()
        guard.load_policy_file(
            "src/agentguard/policies/builtin_policies/no-secret-exposure.yaml"
        )
        result = run_scenario(scenario, guard)
        assert result.passed is True
        assert result.actual == "deny"

    def test_allow_scenario_fails_on_false_positive(self) -> None:
        """Scenario expecting 'allow' fails when action is denied."""
        from agentguard.sandbox.models import Scenario, ScenarioAction
        from agentguard.sandbox.runner import run_scenario

        scenario = Scenario(
            name="bearer-docs",
            description="Discussion of Bearer authentication",
            expected_outcome="allow",
            actions=[
                ScenarioAction(
                    kind="file_write",
                    params={"content": "Bearer token in the Authorization header"},
                ),
            ],
        )
        # A policy that matches "Bearer" too broadly
        guard = Guard()
        guard.load_policy_string("""
name: overly-broad
rules:
  - action: file_write
    deny:
      - pattern: 'Bearer'
    severity: high
""")
        result = run_scenario(scenario, guard)
        assert result.passed is False
        assert result.is_false_positive is True

    def test_deny_scenario_fails_on_false_negative(self) -> None:
        """Scenario expecting 'deny' fails when all actions allowed."""
        from agentguard.sandbox.models import Scenario, ScenarioAction
        from agentguard.sandbox.runner import run_scenario

        scenario = Scenario(
            name="missed-secret",
            description="Secret not caught",
            expected_outcome="deny",
            actions=[
                ScenarioAction(
                    kind="file_write",
                    params={"content": "my_custom_secret_token_12345"},
                ),
            ],
        )
        guard = Guard()  # No policies, nothing denied
        result = run_scenario(scenario, guard)
        assert result.passed is False
        assert result.is_false_negative is True

    def test_multi_action_allow_requires_all_allowed(self) -> None:
        """An 'allow' scenario with multiple actions must allow ALL of them."""
        from agentguard.sandbox.models import Scenario, ScenarioAction
        from agentguard.sandbox.runner import run_scenario

        scenario = Scenario(
            name="multi-read",
            description="Read multiple files",
            expected_outcome="allow",
            actions=[
                ScenarioAction(kind="file_read", params={"path": "/tmp/a.txt"}),
                ScenarioAction(kind="file_read", params={"path": "/tmp/b.txt"}),
                ScenarioAction(kind="file_read", params={"path": "/tmp/c.txt"}),
            ],
        )
        guard = Guard()
        result = run_scenario(scenario, guard)
        assert result.passed is True

    def test_multi_action_deny_needs_at_least_one_denied(self) -> None:
        """A 'deny' scenario passes if ANY action in the sequence is denied."""
        from agentguard.sandbox.models import Scenario, ScenarioAction
        from agentguard.sandbox.runner import run_scenario

        scenario = Scenario(
            name="secret-in-sequence",
            description="One action contains a secret",
            expected_outcome="deny",
            actions=[
                ScenarioAction(kind="file_read", params={"path": "/tmp/ok.txt"}),
                ScenarioAction(
                    kind="file_write",
                    params={"content": "API_KEY = secret123456789012345"},
                ),
            ],
        )
        guard = Guard()
        guard.load_policy_file(
            "src/agentguard/policies/builtin_policies/no-secret-exposure.yaml"
        )
        result = run_scenario(scenario, guard)
        assert result.passed is True
        assert result.actual == "deny"

    def test_result_contains_all_decisions(self) -> None:
        """The result should contain the Decision for each action."""
        from agentguard.sandbox.models import Scenario, ScenarioAction
        from agentguard.sandbox.runner import run_scenario

        scenario = Scenario(
            name="multi",
            description="Multiple actions",
            expected_outcome="allow",
            actions=[
                ScenarioAction(kind="file_read", params={"path": "/tmp/a.txt"}),
                ScenarioAction(kind="file_read", params={"path": "/tmp/b.txt"}),
            ],
        )
        guard = Guard()
        result = run_scenario(scenario, guard)
        assert len(result.decisions) == 2


class TestRunSuite:
    """Tests for running a full suite of scenarios."""

    def test_run_multiple_scenarios(self) -> None:
        from agentguard.sandbox.models import Scenario, ScenarioAction
        from agentguard.sandbox.runner import run_suite

        scenarios = [
            Scenario(
                name="allow-read",
                description="Read a file",
                expected_outcome="allow",
                actions=[ScenarioAction(kind="file_read", params={"path": "/tmp/x"})],
            ),
            Scenario(
                name="deny-secret",
                description="Write a secret",
                expected_outcome="deny",
                actions=[
                    ScenarioAction(
                        kind="file_write",
                        params={"content": "API_KEY = supersecret123456789012345"},
                    ),
                ],
            ),
        ]
        guard = Guard()
        guard.load_policy_file(
            "src/agentguard/policies/builtin_policies/no-secret-exposure.yaml"
        )
        results = run_suite(scenarios, guard)
        assert len(results) == 2
        assert results[0].passed is True
        assert results[1].passed is True

    def test_run_suite_returns_empty_for_empty_input(self) -> None:
        from agentguard.sandbox.runner import run_suite

        results = run_suite([], Guard())
        assert results == []
