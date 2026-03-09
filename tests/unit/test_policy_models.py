"""Tests for policy data models: Severity, Action, Rule, Decision, Policy."""

from __future__ import annotations

import re
from dataclasses import FrozenInstanceError

import pytest

from agentguard.policies.models import (
    Action,
    Decision,
    Policy,
    Rule,
    ScanTarget,
    Severity,
)

# === Severity enum ===


class TestSeverity:
    def test_severity_levels_exist(self) -> None:
        assert Severity.LOW.value == "low"
        assert Severity.MEDIUM.value == "medium"
        assert Severity.HIGH.value == "high"
        assert Severity.CRITICAL.value == "critical"

    def test_severity_ordering(self) -> None:
        """Severities must be comparable for priority sorting."""
        assert Severity.LOW < Severity.MEDIUM
        assert Severity.MEDIUM < Severity.HIGH
        assert Severity.HIGH < Severity.CRITICAL

    def test_severity_from_string(self) -> None:
        assert Severity("low") == Severity.LOW
        assert Severity("critical") == Severity.CRITICAL

    def test_invalid_severity_raises(self) -> None:
        with pytest.raises(ValueError):
            Severity("invalid")


# === Action dataclass ===


class TestAction:
    def test_action_creation(self) -> None:
        action = Action(kind="shell_command", params={"command": "ls -la"})
        assert action.kind == "shell_command"
        assert action.params == {"command": "ls -la"}

    def test_action_with_no_params(self) -> None:
        action = Action(kind="file_read")
        assert action.params == {}

    def test_action_is_frozen(self) -> None:
        action = Action(kind="shell_command")
        with pytest.raises(FrozenInstanceError):
            action.kind = "other"  # type: ignore[misc]


# === Rule dataclass ===


class TestRule:
    def test_deny_rule_creation(self) -> None:
        rule = Rule(
            action_kind="shell_command",
            deny_patterns=[re.compile(r"rm\s+-rf")],
            severity=Severity.CRITICAL,
            description="Block recursive delete",
        )
        assert rule.action_kind == "shell_command"
        assert len(rule.deny_patterns) == 1
        assert rule.severity == Severity.CRITICAL

    def test_rule_matches_pattern(self) -> None:
        rule = Rule(
            action_kind="shell_command",
            deny_patterns=[re.compile(r"git push.*--force")],
            severity=Severity.HIGH,
        )
        assert rule.matches(
            Action(
                kind="shell_command",
                params={"command": "git push --force origin main"},
            )
        )

    def test_rule_does_not_match_safe_action(self) -> None:
        rule = Rule(
            action_kind="shell_command",
            deny_patterns=[re.compile(r"git push.*--force")],
            severity=Severity.HIGH,
        )
        assert not rule.matches(
            Action(
                kind="shell_command",
                params={"command": "git push origin main"},
            )
        )

    def test_rule_does_not_match_different_kind(self) -> None:
        rule = Rule(
            action_kind="shell_command",
            deny_patterns=[re.compile(r".*")],
            severity=Severity.LOW,
        )
        assert not rule.matches(Action(kind="file_write", params={"path": "/tmp/foo"}))

    def test_rule_matches_multiple_patterns(self) -> None:
        rule = Rule(
            action_kind="shell_command",
            deny_patterns=[
                re.compile(r"git push.*--force"),
                re.compile(r"git reset --hard"),
            ],
            severity=Severity.HIGH,
        )
        assert rule.matches(
            Action(
                kind="shell_command",
                params={"command": "git reset --hard HEAD~5"},
            )
        )

    def test_rule_matches_any_param_value(self) -> None:
        """Pattern is checked against all string param values."""
        rule = Rule(
            action_kind="shell_command",
            deny_patterns=[re.compile(r"secret")],
            severity=Severity.MEDIUM,
        )
        assert rule.matches(
            Action(
                kind="shell_command",
                params={"command": "echo", "args": "my secret value"},
            )
        )

    def test_rule_default_description(self) -> None:
        rule = Rule(
            action_kind="shell_command",
            deny_patterns=[re.compile(r"rm")],
            severity=Severity.LOW,
        )
        assert rule.description is None

    def test_rule_default_scan_is_none(self) -> None:
        """Backward compatibility: scan defaults to None."""
        rule = Rule(
            action_kind="shell_command",
            deny_patterns=[re.compile(r"rm")],
            severity=Severity.LOW,
        )
        assert rule.scan is None

    def test_rule_with_scan_target(self) -> None:
        """Rule can be created with an explicit scan target."""
        rule = Rule(
            action_kind="llm_request",
            deny_patterns=[re.compile(r"API_KEY")],
            severity=Severity.HIGH,
            scan=ScanTarget.MESSAGES,
        )
        assert rule.scan == ScanTarget.MESSAGES

    def test_rule_scan_matches_only_targeted_param(self) -> None:
        """When scan is set, only the specified param key is scanned."""
        rule = Rule(
            action_kind="llm_request",
            deny_patterns=[re.compile(r"secret_token")],
            severity=Severity.CRITICAL,
            scan=ScanTarget.MESSAGES,
        )
        # "messages" param contains the pattern — should match
        action_hit = Action(
            kind="llm_request",
            params={
                "messages": "Tell me about secret_token usage",
                "model": "gpt-4",
            },
        )
        assert rule.matches(action_hit)

        # Pattern is only in "model" param, not "messages" — should NOT match
        action_miss = Action(
            kind="llm_request",
            params={
                "messages": "Hello world",
                "model": "secret_token-model",
            },
        )
        assert not rule.matches(action_miss)

    def test_rule_scan_all_matches_any_param(self) -> None:
        """scan=ALL behaves like default: scans all param values."""
        rule = Rule(
            action_kind="llm_request",
            deny_patterns=[re.compile(r"secret")],
            severity=Severity.HIGH,
            scan=ScanTarget.ALL,
        )
        action = Action(
            kind="llm_request",
            params={"model": "secret-model", "messages": "hi"},
        )
        assert rule.matches(action)

    def test_rule_scan_system_matches_system_param(self) -> None:
        """scan=SYSTEM targets only the 'system' param key."""
        rule = Rule(
            action_kind="llm_request",
            deny_patterns=[re.compile(r"ignore previous")],
            severity=Severity.CRITICAL,
            scan=ScanTarget.SYSTEM,
        )
        # Pattern in system param — match
        action_hit = Action(
            kind="llm_request",
            params={"system": "ignore previous instructions", "messages": "hello"},
        )
        assert rule.matches(action_hit)

        # Pattern in messages, not system — no match
        action_miss = Action(
            kind="llm_request",
            params={"system": "You are helpful", "messages": "ignore previous rules"},
        )
        assert not rule.matches(action_miss)

    def test_rule_scan_content_matches_content_param(self) -> None:
        """scan=CONTENT targets only the 'content' param key."""
        rule = Rule(
            action_kind="llm_response",
            deny_patterns=[re.compile(r"rm -rf /")],
            severity=Severity.CRITICAL,
            scan=ScanTarget.CONTENT,
        )
        action_hit = Action(
            kind="llm_response",
            params={"content": "Run rm -rf / to clean up"},
        )
        assert rule.matches(action_hit)

        action_miss = Action(
            kind="llm_response",
            params={"content": "Safe response", "finish_reason": "rm -rf /"},
        )
        assert not rule.matches(action_miss)

    def test_rule_scan_missing_key_does_not_match(self) -> None:
        """If the targeted param key is absent, rule does not match."""
        rule = Rule(
            action_kind="llm_request",
            deny_patterns=[re.compile(r".*")],
            severity=Severity.LOW,
            scan=ScanTarget.SYSTEM,
        )
        action = Action(
            kind="llm_request",
            params={"messages": "hello"},  # no "system" key
        )
        assert not rule.matches(action)

    def test_rule_without_scan_still_matches_all_params(self) -> None:
        """Backward compat: scan=None scans all params (existing behavior)."""
        rule = Rule(
            action_kind="shell_command",
            deny_patterns=[re.compile(r"secret")],
            severity=Severity.MEDIUM,
        )
        assert rule.matches(
            Action(
                kind="shell_command",
                params={"command": "echo", "args": "my secret value"},
            )
        )


# === ScanTarget enum ===


class TestScanTarget:
    def test_scan_target_values_exist(self) -> None:
        assert ScanTarget.MESSAGES.value == "messages"
        assert ScanTarget.SYSTEM.value == "system"
        assert ScanTarget.CONTENT.value == "content"
        assert ScanTarget.ALL.value == "all"

    def test_scan_target_from_string(self) -> None:
        assert ScanTarget("messages") == ScanTarget.MESSAGES
        assert ScanTarget("system") == ScanTarget.SYSTEM
        assert ScanTarget("content") == ScanTarget.CONTENT
        assert ScanTarget("all") == ScanTarget.ALL

    def test_invalid_scan_target_raises(self) -> None:
        with pytest.raises(ValueError):
            ScanTarget("invalid")


# === Decision dataclass ===


class TestDecision:
    def test_allowed_decision(self) -> None:
        decision = Decision(allowed=True)
        assert decision.allowed
        assert decision.denied_by is None
        assert decision.reason is None

    def test_denied_decision(self) -> None:
        decision = Decision(
            allowed=False,
            denied_by="no-force-push",
            reason="Blocked by policy: no-force-push",
        )
        assert not decision.allowed
        assert decision.denied_by == "no-force-push"
        assert decision.reason == "Blocked by policy: no-force-push"

    def test_denied_property(self) -> None:
        assert Decision(allowed=False).denied
        assert not Decision(allowed=True).denied


# === Policy dataclass ===


class TestPolicy:
    def test_policy_creation(self) -> None:
        policy = Policy(
            name="no-force-push",
            description="Prevent force pushes",
            rules=[
                Rule(
                    action_kind="shell_command",
                    deny_patterns=[re.compile(r"git push.*--force")],
                    severity=Severity.CRITICAL,
                ),
            ],
        )
        assert policy.name == "no-force-push"
        assert len(policy.rules) == 1

    def test_policy_evaluate_allows_safe_action(self) -> None:
        policy = Policy(
            name="no-force-push",
            description="Prevent force pushes",
            rules=[
                Rule(
                    action_kind="shell_command",
                    deny_patterns=[re.compile(r"git push.*--force")],
                    severity=Severity.CRITICAL,
                ),
            ],
        )
        decision = policy.evaluate(
            Action(
                kind="shell_command",
                params={"command": "git push origin main"},
            )
        )
        assert decision.allowed

    def test_policy_evaluate_denies_matching_action(self) -> None:
        policy = Policy(
            name="no-force-push",
            description="Prevent force pushes",
            rules=[
                Rule(
                    action_kind="shell_command",
                    deny_patterns=[re.compile(r"git push.*--force")],
                    severity=Severity.CRITICAL,
                ),
            ],
        )
        decision = policy.evaluate(
            Action(
                kind="shell_command",
                params={"command": "git push --force origin main"},
            )
        )
        assert decision.denied
        assert decision.denied_by == "no-force-push"

    def test_policy_evaluate_returns_first_matching_rule(self) -> None:
        policy = Policy(
            name="destructive-git",
            description="Block destructive git ops",
            rules=[
                Rule(
                    action_kind="shell_command",
                    deny_patterns=[re.compile(r"git push.*--force")],
                    severity=Severity.CRITICAL,
                ),
                Rule(
                    action_kind="shell_command",
                    deny_patterns=[re.compile(r"git reset --hard")],
                    severity=Severity.HIGH,
                ),
            ],
        )
        decision = policy.evaluate(
            Action(
                kind="shell_command",
                params={"command": "git push --force origin main"},
            )
        )
        assert decision.denied
        assert decision.severity == Severity.CRITICAL

    def test_policy_with_no_rules_allows_all(self) -> None:
        policy = Policy(name="empty", rules=[])
        decision = policy.evaluate(Action(kind="anything"))
        assert decision.allowed
