"""Tests for the Guard class (M1.3)."""

from __future__ import annotations

import re
import textwrap
from typing import TYPE_CHECKING

from agentguard.policies.guard import Guard

if TYPE_CHECKING:
    from pathlib import Path
from agentguard.policies.models import (
    Decision,
    Policy,
    Rule,
    Severity,
)


def _make_policy(
    name: str = "test-policy",
    action_kind: str = "shell_command",
    pattern: str = "dangerous",
    severity: Severity = Severity.HIGH,
) -> Policy:
    """Helper to create a simple single-rule policy."""
    return Policy(
        name=name,
        rules=[
            Rule(
                action_kind=action_kind,
                deny_patterns=[re.compile(pattern)],
                severity=severity,
            )
        ],
    )


class TestGuardInit:
    def test_empty_guard(self) -> None:
        guard = Guard()
        assert len(guard.policies) == 0

    def test_guard_with_policies(self) -> None:
        p1 = _make_policy("p1")
        p2 = _make_policy("p2")
        guard = Guard(policies=[p1, p2])
        assert len(guard.policies) == 2


class TestGuardAddPolicy:
    def test_add_single_policy(self) -> None:
        guard = Guard()
        policy = _make_policy()
        guard.add_policy(policy)
        assert len(guard.policies) == 1
        assert guard.policies[0] is policy

    def test_add_multiple_policies(self) -> None:
        guard = Guard()
        guard.add_policy(_make_policy("p1"))
        guard.add_policy(_make_policy("p2"))
        assert len(guard.policies) == 2

    def test_add_policy_returns_self_for_chaining(self) -> None:
        guard = Guard()
        result = guard.add_policy(_make_policy())
        assert result is guard


class TestGuardCheck:
    def test_no_policies_allows(self) -> None:
        guard = Guard()
        result = guard.check("shell_command", command="rm -rf /")
        assert result.allowed

    def test_matching_policy_denies(self) -> None:
        guard = Guard()
        guard.add_policy(_make_policy(pattern="rm -rf"))
        result = guard.check("shell_command", command="rm -rf /")
        assert result.denied
        assert result.denied_by == "test-policy"

    def test_non_matching_policy_allows(self) -> None:
        guard = Guard()
        guard.add_policy(_make_policy(pattern="rm -rf"))
        result = guard.check("shell_command", command="ls -la")
        assert result.allowed

    def test_wrong_action_kind_allows(self) -> None:
        guard = Guard()
        guard.add_policy(_make_policy(action_kind="file_write", pattern="secret"))
        result = guard.check("shell_command", command="echo secret")
        assert result.allowed

    def test_first_denying_policy_wins(self) -> None:
        guard = Guard()
        guard.add_policy(
            _make_policy("policy-a", pattern="danger", severity=Severity.HIGH),
        )
        guard.add_policy(
            _make_policy("policy-b", pattern="danger", severity=Severity.CRITICAL),
        )
        result = guard.check("shell_command", command="danger zone")
        assert result.denied_by == "policy-a"
        assert result.severity == Severity.HIGH

    def test_check_returns_decision(self) -> None:
        guard = Guard()
        result = guard.check("shell_command", command="ls")
        assert isinstance(result, Decision)

    def test_check_with_multiple_params(self) -> None:
        guard = Guard()
        guard.add_policy(_make_policy(action_kind="file_write", pattern=r"\.env$"))
        result = guard.check("file_write", path="/app/.env", content="SECRET=123")
        assert result.denied

    def test_check_passes_when_pattern_matches_other_kind(self) -> None:
        guard = Guard()
        guard.add_policy(_make_policy(action_kind="shell_command", pattern="secret"))
        result = guard.check("file_write", content="secret")
        assert result.allowed

    def test_check_denied_has_reason(self) -> None:
        guard = Guard()
        guard.add_policy(_make_policy("my-policy", pattern="bad"))
        result = guard.check("shell_command", command="bad thing")
        assert result.reason is not None
        assert "my-policy" in result.reason

    def test_check_allowed_has_no_reason(self) -> None:
        guard = Guard()
        guard.add_policy(_make_policy(pattern="bad"))
        result = guard.check("shell_command", command="good thing")
        assert result.reason is None
        assert result.denied_by is None
        assert result.severity is None


class TestGuardLoadYaml:
    def test_load_from_string(self) -> None:
        yaml_str = textwrap.dedent("""\
            name: yaml-policy
            rules:
              - action: shell_command
                deny:
                  - pattern: "git push.*--force"
                severity: critical
        """)
        guard = Guard()
        guard.load_policy_string(yaml_str)
        assert len(guard.policies) == 1
        result = guard.check("shell_command", command="git push --force origin main")
        assert result.denied

    def test_load_from_file(self, tmp_path: Path) -> None:
        policy_file = tmp_path / "policy.yaml"
        policy_file.write_text(
            textwrap.dedent("""\
            name: file-policy
            rules:
              - action: file_write
                deny:
                  - pattern: "password"
                severity: high
        """)
        )
        guard = Guard()
        guard.load_policy_file(policy_file)
        assert len(guard.policies) == 1
        result = guard.check("file_write", content="password=hunter2")
        assert result.denied

    def test_load_multiple_sources(self, tmp_path: Path) -> None:
        yaml_str = textwrap.dedent("""\
            name: string-policy
            rules:
              - action: shell_command
                deny:
                  - pattern: "rm"
                severity: low
        """)
        policy_file = tmp_path / "file-policy.yaml"
        policy_file.write_text(
            textwrap.dedent("""\
            name: file-policy
            rules:
              - action: file_write
                deny:
                  - pattern: "secret"
                severity: medium
        """)
        )
        guard = Guard()
        guard.load_policy_string(yaml_str)
        guard.load_policy_file(policy_file)
        guard.add_policy(_make_policy("code-policy", pattern="eval"))
        assert len(guard.policies) == 3
