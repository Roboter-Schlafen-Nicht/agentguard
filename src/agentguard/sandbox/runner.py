"""Sandbox scenario runner.

Executes scenarios through the Guard and produces ScenarioResults.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from agentguard.sandbox.models import ScenarioResult

if TYPE_CHECKING:
    from agentguard.policies.guard import Guard
    from agentguard.policies.models import Decision
    from agentguard.sandbox.models import Scenario


def run_scenario(scenario: Scenario, guard: Guard) -> ScenarioResult:
    """Run a single scenario through the Guard.

    Each action in the scenario is evaluated against the Guard.
    For an "allow" scenario, ALL actions must be allowed.
    For a "deny" scenario, at least ONE action must be denied.

    Args:
        scenario: The scenario to run.
        guard: The Guard instance with loaded policies.

    Returns:
        A ScenarioResult with the outcome.
    """
    decisions: list[Decision] = []
    any_denied = False

    for action in scenario.actions:
        decision = guard.check(action.kind, **action.params)
        decisions.append(decision)
        if decision.denied:
            any_denied = True

    actual = "deny" if any_denied else "allow"
    passed = actual == scenario.expected_outcome

    failure_reason = None
    if not passed:
        if scenario.expected_outcome == "allow" and any_denied:
            denied_by = [d.denied_by for d in decisions if d.denied]
            failure_reason = (
                f"False positive: blocked by {', '.join(str(n) for n in denied_by)}"
            )
        elif scenario.expected_outcome == "deny" and not any_denied:
            failure_reason = "False negative: no action was denied"

    return ScenarioResult(
        scenario_name=scenario.name,
        expected=scenario.expected_outcome,
        actual=actual,
        passed=passed,
        decisions=decisions,
        failure_reason=failure_reason,
    )


def run_suite(scenarios: list[Scenario], guard: Guard) -> list[ScenarioResult]:
    """Run a suite of scenarios through the Guard.

    Args:
        scenarios: List of scenarios to run.
        guard: The Guard instance with loaded policies.

    Returns:
        List of ScenarioResults, one per scenario.
    """
    return [run_scenario(s, guard) for s in scenarios]
