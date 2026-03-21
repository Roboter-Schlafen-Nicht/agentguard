"""Tests for conditional policies (M11).

Covers:
- Condition and Context data models
- Time-based conditions (time_after, time_before, weekdays)
- Environment-based conditions
- Branch-based conditions
- Combined conditions (AND semantics)
- Rule evaluation with conditions
- Policy evaluation with context
- Guard.check() with context
- YAML parsing of conditions
- Edge cases and backward compatibility
"""

from __future__ import annotations

import re
from datetime import datetime, time, timezone

import pytest

from agentguard.policies.guard import Guard
from agentguard.policies.loader import load_policy_from_string
from agentguard.policies.models import (
    Action,
    Condition,
    Context,
    Policy,
    Rule,
    Severity,
)


def _make_rule(
    action_kind: str = "shell_command",
    pattern: str = "rm -rf",
    severity: Severity = Severity.CRITICAL,
    conditions: Condition | None = None,
) -> Rule:
    """Helper to create a Rule with a single deny pattern."""
    return Rule(
        action_kind=action_kind,
        deny_patterns=[re.compile(pattern)],
        severity=severity,
        conditions=conditions,
    )


# --- Condition model ---


class TestCondition:
    """Tests for the Condition dataclass."""

    def test_empty_condition_is_valid(self) -> None:
        cond = Condition()
        assert cond.time_after is None
        assert cond.time_before is None
        assert cond.environment is None
        assert cond.branch is None
        assert cond.weekdays is None

    def test_time_after_only(self) -> None:
        cond = Condition(time_after=time(9, 0))
        assert cond.time_after == time(9, 0)

    def test_time_before_only(self) -> None:
        cond = Condition(time_before=time(17, 0))
        assert cond.time_before == time(17, 0)

    def test_environment_set(self) -> None:
        cond = Condition(environment="production")
        assert cond.environment == "production"

    def test_branch_set(self) -> None:
        cond = Condition(branch="main")
        assert cond.branch == "main"

    def test_weekdays_set(self) -> None:
        cond = Condition(weekdays=[0, 1, 2, 3, 4])  # Mon-Fri
        assert cond.weekdays == [0, 1, 2, 3, 4]

    def test_all_fields(self) -> None:
        cond = Condition(
            time_after=time(9, 0),
            time_before=time(17, 0),
            environment="production",
            branch="main",
            weekdays=[0, 1, 2, 3, 4],
        )
        assert cond.time_after == time(9, 0)
        assert cond.time_before == time(17, 0)
        assert cond.environment == "production"
        assert cond.branch == "main"
        assert cond.weekdays == [0, 1, 2, 3, 4]


# --- Context model ---


class TestContext:
    """Tests for the Context dataclass."""

    def test_default_context(self) -> None:
        ctx = Context()
        assert ctx.time is None
        assert ctx.environment is None
        assert ctx.branch is None
        assert ctx.variables == {}

    def test_with_time(self) -> None:
        t = datetime(2026, 3, 21, 14, 30, tzinfo=timezone.utc)
        ctx = Context(time=t)
        assert ctx.time == t

    def test_with_environment(self) -> None:
        ctx = Context(environment="staging")
        assert ctx.environment == "staging"

    def test_with_branch(self) -> None:
        ctx = Context(branch="feature/new")
        assert ctx.branch == "feature/new"

    def test_with_variables(self) -> None:
        ctx = Context(variables={"team": "engineering"})
        assert ctx.variables == {"team": "engineering"}


# --- Condition evaluation ---


class TestConditionEvaluation:
    """Tests for Condition.is_met(context) evaluation."""

    def test_empty_condition_always_met(self) -> None:
        """Condition with no fields set is always met."""
        cond = Condition()
        ctx = Context()
        assert cond.is_met(ctx) is True

    def test_empty_condition_met_with_any_context(self) -> None:
        cond = Condition()
        ctx = Context(environment="production", branch="main")
        assert cond.is_met(ctx) is True

    # --- Time-based ---

    def test_time_after_met(self) -> None:
        """Current time is after the threshold."""
        cond = Condition(time_after=time(9, 0))
        ctx = Context(
            time=datetime(2026, 3, 21, 10, 0, tzinfo=timezone.utc),
        )
        assert cond.is_met(ctx) is True

    def test_time_after_not_met(self) -> None:
        """Current time is before the threshold."""
        cond = Condition(time_after=time(9, 0))
        ctx = Context(
            time=datetime(2026, 3, 21, 8, 0, tzinfo=timezone.utc),
        )
        assert cond.is_met(ctx) is False

    def test_time_before_met(self) -> None:
        """Current time is before the threshold."""
        cond = Condition(time_before=time(17, 0))
        ctx = Context(
            time=datetime(2026, 3, 21, 16, 0, tzinfo=timezone.utc),
        )
        assert cond.is_met(ctx) is True

    def test_time_before_not_met(self) -> None:
        """Current time is after the threshold."""
        cond = Condition(time_before=time(17, 0))
        ctx = Context(
            time=datetime(2026, 3, 21, 18, 0, tzinfo=timezone.utc),
        )
        assert cond.is_met(ctx) is False

    def test_time_window(self) -> None:
        """time_after + time_before define a window; inside = met."""
        cond = Condition(time_after=time(9, 0), time_before=time(17, 0))
        ctx = Context(
            time=datetime(2026, 3, 21, 12, 0, tzinfo=timezone.utc),
        )
        assert cond.is_met(ctx) is True

    def test_time_window_outside(self) -> None:
        """Outside the time window = not met."""
        cond = Condition(time_after=time(9, 0), time_before=time(17, 0))
        ctx = Context(
            time=datetime(2026, 3, 21, 20, 0, tzinfo=timezone.utc),
        )
        assert cond.is_met(ctx) is False

    def test_time_condition_without_context_time_not_met(self) -> None:
        """Time condition without context time = not met (fail-closed)."""
        cond = Condition(time_after=time(9, 0))
        ctx = Context()
        assert cond.is_met(ctx) is False

    def test_weekdays_met(self) -> None:
        """Friday is in the weekday list."""
        cond = Condition(weekdays=[0, 1, 2, 3, 4])  # Mon-Fri
        # 2026-03-20 is a Friday (weekday=4)
        ctx = Context(
            time=datetime(2026, 3, 20, 12, 0, tzinfo=timezone.utc),
        )
        assert cond.is_met(ctx) is True

    def test_weekdays_not_met(self) -> None:
        """Saturday is not in the weekday list."""
        cond = Condition(weekdays=[0, 1, 2, 3, 4])  # Mon-Fri
        # 2026-03-21 is a Saturday (weekday=5)
        ctx = Context(
            time=datetime(2026, 3, 21, 12, 0, tzinfo=timezone.utc),
        )
        assert cond.is_met(ctx) is False

    def test_weekdays_without_context_time_not_met(self) -> None:
        """Weekday condition without context time = not met."""
        cond = Condition(weekdays=[0, 1, 2, 3, 4])
        ctx = Context()
        assert cond.is_met(ctx) is False

    # --- Environment-based ---

    def test_environment_met(self) -> None:
        cond = Condition(environment="production")
        ctx = Context(environment="production")
        assert cond.is_met(ctx) is True

    def test_environment_not_met(self) -> None:
        cond = Condition(environment="production")
        ctx = Context(environment="staging")
        assert cond.is_met(ctx) is False

    def test_environment_case_insensitive(self) -> None:
        cond = Condition(environment="Production")
        ctx = Context(environment="production")
        assert cond.is_met(ctx) is True

    def test_environment_without_context_env_not_met(self) -> None:
        """Environment condition without context environment = not met."""
        cond = Condition(environment="production")
        ctx = Context()
        assert cond.is_met(ctx) is False

    # --- Branch-based ---

    def test_branch_exact_match(self) -> None:
        cond = Condition(branch="main")
        ctx = Context(branch="main")
        assert cond.is_met(ctx) is True

    def test_branch_not_met(self) -> None:
        cond = Condition(branch="main")
        ctx = Context(branch="feature/new")
        assert cond.is_met(ctx) is False

    def test_branch_glob_pattern(self) -> None:
        """Branch supports fnmatch-style glob patterns."""
        cond = Condition(branch="feature/*")
        ctx = Context(branch="feature/new-thing")
        assert cond.is_met(ctx) is True

    def test_branch_glob_not_met(self) -> None:
        cond = Condition(branch="feature/*")
        ctx = Context(branch="main")
        assert cond.is_met(ctx) is False

    def test_branch_without_context_branch_not_met(self) -> None:
        """Branch condition without context branch = not met."""
        cond = Condition(branch="main")
        ctx = Context()
        assert cond.is_met(ctx) is False

    # --- Combined conditions (AND semantics) ---

    def test_all_conditions_met(self) -> None:
        cond = Condition(
            time_after=time(9, 0),
            time_before=time(17, 0),
            environment="production",
            branch="main",
        )
        ctx = Context(
            time=datetime(2026, 3, 20, 12, 0, tzinfo=timezone.utc),
            environment="production",
            branch="main",
        )
        assert cond.is_met(ctx) is True

    def test_one_condition_not_met(self) -> None:
        """If any one condition fails, the whole is not met."""
        cond = Condition(
            environment="production",
            branch="main",
        )
        ctx = Context(
            environment="staging",
            branch="main",
        )
        assert cond.is_met(ctx) is False


# --- Rule with conditions ---


class TestRuleWithConditions:
    """Tests for Rule.matches() with conditions."""

    def test_rule_without_conditions_always_evaluated(self) -> None:
        """Backward compat: no conditions = always match if pattern matches."""
        rule = _make_rule()
        action = Action(kind="shell_command", params={"command": "rm -rf /"})
        assert rule.matches(action) is True

    def test_rule_with_met_condition_matches(self) -> None:
        """Rule matches when conditions are met and pattern matches."""
        rule = _make_rule(
            conditions=Condition(environment="production"),
        )
        action = Action(kind="shell_command", params={"command": "rm -rf /"})
        ctx = Context(environment="production")
        assert rule.matches(action, context=ctx) is True

    def test_rule_with_unmet_condition_skipped(self) -> None:
        """Rule is skipped when conditions are not met."""
        rule = _make_rule(
            conditions=Condition(environment="production"),
        )
        action = Action(kind="shell_command", params={"command": "rm -rf /"})
        ctx = Context(environment="staging")
        assert rule.matches(action, context=ctx) is False

    def test_rule_with_conditions_no_context_skipped(self) -> None:
        """Rule with conditions but no context passed = skipped (fail-open)."""
        rule = _make_rule(
            conditions=Condition(environment="production"),
        )
        action = Action(kind="shell_command", params={"command": "rm -rf /"})
        assert rule.matches(action) is False

    def test_rule_pattern_not_matched_even_with_conditions_met(self) -> None:
        """Even if conditions are met, pattern must also match."""
        rule = _make_rule(
            conditions=Condition(environment="production"),
        )
        action = Action(kind="shell_command", params={"command": "echo hello"})
        ctx = Context(environment="production")
        assert rule.matches(action, context=ctx) is False


# --- Policy evaluation with context ---


class TestPolicyWithContext:
    """Tests for Policy.evaluate() with context."""

    def test_evaluate_with_context_denies(self) -> None:
        policy = Policy(
            name="conditional-deny",
            rules=[
                _make_rule(conditions=Condition(environment="production")),
            ],
        )
        action = Action(kind="shell_command", params={"command": "rm -rf /"})
        ctx = Context(environment="production")
        decision = policy.evaluate(action, context=ctx)
        assert decision.denied is True

    def test_evaluate_with_context_allows(self) -> None:
        policy = Policy(
            name="conditional-deny",
            rules=[
                _make_rule(conditions=Condition(environment="production")),
            ],
        )
        action = Action(kind="shell_command", params={"command": "rm -rf /"})
        ctx = Context(environment="staging")
        decision = policy.evaluate(action, context=ctx)
        assert decision.allowed is True

    def test_evaluate_without_context_backward_compat(self) -> None:
        """Policy with unconditional rules still works without context."""
        policy = Policy(
            name="always-deny",
            rules=[_make_rule()],
        )
        action = Action(kind="shell_command", params={"command": "rm -rf /"})
        decision = policy.evaluate(action)
        assert decision.denied is True


# --- Guard.check() with context ---


class TestGuardWithContext:
    """Tests for Guard.check() with context."""

    def test_check_with_context_denies(self) -> None:
        guard = Guard(
            policies=[
                Policy(
                    name="prod-only",
                    rules=[
                        _make_rule(
                            conditions=Condition(environment="production"),
                        ),
                    ],
                ),
            ],
        )
        decision = guard.check(
            "shell_command",
            Context(environment="production"),
            command="rm -rf /",
        )
        assert decision.denied is True

    def test_check_with_context_allows(self) -> None:
        guard = Guard(
            policies=[
                Policy(
                    name="prod-only",
                    rules=[
                        _make_rule(
                            conditions=Condition(environment="production"),
                        ),
                    ],
                ),
            ],
        )
        decision = guard.check(
            "shell_command",
            Context(environment="staging"),
            command="rm -rf /",
        )
        assert decision.allowed is True

    def test_check_without_context_backward_compat(self) -> None:
        """Guard.check() without context works for unconditional rules."""
        guard = Guard(
            policies=[
                Policy(name="always-deny", rules=[_make_rule()]),
            ],
        )
        decision = guard.check("shell_command", command="rm -rf /")
        assert decision.denied is True


# --- YAML loading with conditions ---


class TestYAMLConditions:
    """Tests for YAML parsing of conditions."""

    def test_load_policy_with_time_conditions(self) -> None:
        yaml_str = """
name: time-based
rules:
  - action: shell_command
    severity: critical
    conditions:
      time_after: "09:00"
      time_before: "17:00"
    deny:
      - pattern: 'rm -rf'
"""
        policy = load_policy_from_string(yaml_str)
        assert policy.name == "time-based"
        rule = policy.rules[0]
        assert rule.conditions is not None
        assert rule.conditions.time_after == time(9, 0)
        assert rule.conditions.time_before == time(17, 0)

    def test_load_policy_with_environment_condition(self) -> None:
        yaml_str = """
name: env-based
rules:
  - action: shell_command
    severity: critical
    conditions:
      environment: production
    deny:
      - pattern: 'rm -rf'
"""
        policy = load_policy_from_string(yaml_str)
        rule = policy.rules[0]
        assert rule.conditions is not None
        assert rule.conditions.environment == "production"

    def test_load_policy_with_branch_condition(self) -> None:
        yaml_str = """
name: branch-based
rules:
  - action: shell_command
    severity: critical
    conditions:
      branch: main
    deny:
      - pattern: 'rm -rf'
"""
        policy = load_policy_from_string(yaml_str)
        rule = policy.rules[0]
        assert rule.conditions is not None
        assert rule.conditions.branch == "main"

    def test_load_policy_with_weekdays_condition(self) -> None:
        yaml_str = """
name: weekday-based
rules:
  - action: shell_command
    severity: critical
    conditions:
      weekdays: [0, 1, 2, 3, 4]
    deny:
      - pattern: 'rm -rf'
"""
        policy = load_policy_from_string(yaml_str)
        rule = policy.rules[0]
        assert rule.conditions is not None
        assert rule.conditions.weekdays == [0, 1, 2, 3, 4]

    def test_load_policy_with_all_conditions(self) -> None:
        yaml_str = """
name: full-conditional
rules:
  - action: shell_command
    severity: critical
    conditions:
      time_after: "08:30"
      time_before: "18:30"
      environment: production
      branch: "release/*"
      weekdays: [0, 1, 2, 3, 4]
    deny:
      - pattern: 'rm -rf'
"""
        policy = load_policy_from_string(yaml_str)
        rule = policy.rules[0]
        assert rule.conditions is not None
        assert rule.conditions.time_after == time(8, 30)
        assert rule.conditions.time_before == time(18, 30)
        assert rule.conditions.environment == "production"
        assert rule.conditions.branch == "release/*"
        assert rule.conditions.weekdays == [0, 1, 2, 3, 4]

    def test_load_policy_without_conditions_backward_compat(self) -> None:
        yaml_str = """
name: no-conditions
rules:
  - action: shell_command
    severity: critical
    deny:
      - pattern: 'rm -rf'
"""
        policy = load_policy_from_string(yaml_str)
        rule = policy.rules[0]
        assert rule.conditions is None

    def test_invalid_time_format_raises(self) -> None:
        yaml_str = """
name: bad-time
rules:
  - action: shell_command
    severity: critical
    conditions:
      time_after: "not-a-time"
    deny:
      - pattern: 'rm -rf'
"""
        with pytest.raises(ValueError, match="time_after"):
            load_policy_from_string(yaml_str)

    def test_invalid_weekday_raises(self) -> None:
        yaml_str = """
name: bad-weekday
rules:
  - action: shell_command
    severity: critical
    conditions:
      weekdays: [0, 7]
    deny:
      - pattern: 'rm -rf'
"""
        with pytest.raises(ValueError, match="weekday"):
            load_policy_from_string(yaml_str)

    def test_unknown_condition_field_raises(self) -> None:
        yaml_str = """
name: bad-field
rules:
  - action: shell_command
    severity: critical
    conditions:
      unknown_field: value
    deny:
      - pattern: 'rm -rf'
"""
        with pytest.raises(ValueError, match="Unknown condition"):
            load_policy_from_string(yaml_str)


# --- End-to-end: YAML → Guard → conditional check ---


class TestEndToEnd:
    """End-to-end tests: load YAML, create guard, check with context."""

    def test_conditional_policy_enforced_in_production(self) -> None:
        yaml_str = """
name: prod-protection
rules:
  - action: shell_command
    severity: critical
    conditions:
      environment: production
    deny:
      - pattern: 'rm -rf'
"""
        guard = Guard()
        guard.load_policy_string(yaml_str)
        decision = guard.check(
            "shell_command",
            Context(environment="production"),
            command="rm -rf /",
        )
        assert decision.denied is True
        assert decision.denied_by == "prod-protection"

    def test_conditional_policy_not_enforced_in_staging(self) -> None:
        yaml_str = """
name: prod-protection
rules:
  - action: shell_command
    severity: critical
    conditions:
      environment: production
    deny:
      - pattern: 'rm -rf'
"""
        guard = Guard()
        guard.load_policy_string(yaml_str)
        decision = guard.check(
            "shell_command",
            Context(environment="staging"),
            command="rm -rf /",
        )
        assert decision.allowed is True

    def test_time_based_enforcement(self) -> None:
        yaml_str = """
name: business-hours-only
rules:
  - action: shell_command
    severity: high
    conditions:
      time_after: "09:00"
      time_before: "17:00"
    deny:
      - pattern: 'deploy'
"""
        guard = Guard()
        guard.load_policy_string(yaml_str)

        # During business hours: denied
        during = guard.check(
            "shell_command",
            Context(
                time=datetime(2026, 3, 20, 12, 0, tzinfo=timezone.utc),
            ),
            command="deploy production",
        )
        assert during.denied is True

        # Outside business hours: allowed
        outside = guard.check(
            "shell_command",
            Context(
                time=datetime(2026, 3, 20, 20, 0, tzinfo=timezone.utc),
            ),
            command="deploy production",
        )
        assert outside.allowed is True
