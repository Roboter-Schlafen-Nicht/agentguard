"""Tests for built-in policies (M1.4)."""

from __future__ import annotations

import pytest

from agentguard.policies.builtins import (
    list_builtins,
    load_all_builtins,
    load_builtin,
)
from agentguard.policies.models import Action, Policy


class TestListBuiltins:
    def test_returns_list_of_strings(self) -> None:
        result = list_builtins()
        assert isinstance(result, list)
        for name in result:
            assert isinstance(name, str)

    def test_contains_expected_policies(self) -> None:
        names = list_builtins()
        assert "no-force-push" in names
        assert "no-secret-exposure" in names
        assert "no-data-deletion" in names


class TestLoadBuiltin:
    def test_load_no_force_push(self) -> None:
        policy = load_builtin("no-force-push")
        assert isinstance(policy, Policy)
        assert policy.name == "no-force-push"

    def test_load_no_secret_exposure(self) -> None:
        policy = load_builtin("no-secret-exposure")
        assert isinstance(policy, Policy)
        assert policy.name == "no-secret-exposure"

    def test_load_no_data_deletion(self) -> None:
        policy = load_builtin("no-data-deletion")
        assert isinstance(policy, Policy)
        assert policy.name == "no-data-deletion"

    def test_nonexistent_builtin_raises(self) -> None:
        with pytest.raises(ValueError, match="not-a-real-policy"):
            load_builtin("not-a-real-policy")


class TestLoadAllBuiltins:
    def test_returns_list_of_policies(self) -> None:
        policies = load_all_builtins()
        assert isinstance(policies, list)
        assert len(policies) >= 3
        for p in policies:
            assert isinstance(p, Policy)

    def test_all_names_match(self) -> None:
        policies = load_all_builtins()
        names = {p.name for p in policies}
        assert "no-force-push" in names
        assert "no-secret-exposure" in names
        assert "no-data-deletion" in names


class TestBuiltinPolicyBehavior:
    """Verify each built-in policy actually blocks what it should."""

    def test_no_force_push_blocks_force(self) -> None:
        policy = load_builtin("no-force-push")
        action = Action(
            kind="shell_command",
            params={"command": "git push --force origin main"},
        )
        decision = policy.evaluate(action)
        assert decision.denied

    def test_no_force_push_allows_normal_push(self) -> None:
        policy = load_builtin("no-force-push")
        action = Action(
            kind="shell_command",
            params={"command": "git push origin main"},
        )
        decision = policy.evaluate(action)
        assert decision.allowed

    def test_no_force_push_blocks_force_with_lease(self) -> None:
        policy = load_builtin("no-force-push")
        action = Action(
            kind="shell_command",
            params={"command": "git push --force-with-lease origin main"},
        )
        decision = policy.evaluate(action)
        assert decision.denied

    def test_no_force_push_blocks_hard_reset(self) -> None:
        policy = load_builtin("no-force-push")
        action = Action(
            kind="shell_command",
            params={"command": "git reset --hard HEAD~3"},
        )
        decision = policy.evaluate(action)
        assert decision.denied

    def test_no_force_push_blocks_branch_delete(self) -> None:
        policy = load_builtin("no-force-push")
        action = Action(
            kind="shell_command",
            params={"command": "git branch -D feature/test"},
        )
        decision = policy.evaluate(action)
        assert decision.denied

    def test_no_secret_exposure_blocks_env_file(self) -> None:
        policy = load_builtin("no-secret-exposure")
        action = Action(kind="file_write", params={"path": "/app/.env"})
        decision = policy.evaluate(action)
        assert decision.denied

    def test_no_secret_exposure_blocks_aws_credentials(self) -> None:
        policy = load_builtin("no-secret-exposure")
        action = Action(
            kind="file_write",
            params={"path": "/home/user/.aws/credentials"},
        )
        decision = policy.evaluate(action)
        assert decision.denied

    def test_no_secret_exposure_blocks_api_key_in_content(self) -> None:
        policy = load_builtin("no-secret-exposure")
        action = Action(
            kind="file_write",
            params={"path": "config.py", "content": 'API_KEY = "sk-abc123"'},
        )
        decision = policy.evaluate(action)
        assert decision.denied

    def test_no_secret_exposure_allows_normal_file(self) -> None:
        policy = load_builtin("no-secret-exposure")
        action = Action(
            kind="file_write",
            params={"path": "src/main.py", "content": "print('hello')"},
        )
        decision = policy.evaluate(action)
        assert decision.allowed

    def test_no_data_deletion_blocks_rm_rf(self) -> None:
        policy = load_builtin("no-data-deletion")
        action = Action(kind="shell_command", params={"command": "rm -rf /"})
        decision = policy.evaluate(action)
        assert decision.denied

    def test_no_data_deletion_blocks_drop_database(self) -> None:
        policy = load_builtin("no-data-deletion")
        action = Action(
            kind="shell_command",
            params={"command": "DROP DATABASE production"},
        )
        decision = policy.evaluate(action)
        assert decision.denied

    def test_no_data_deletion_blocks_truncate_table(self) -> None:
        policy = load_builtin("no-data-deletion")
        action = Action(
            kind="shell_command",
            params={"command": "TRUNCATE TABLE users"},
        )
        decision = policy.evaluate(action)
        assert decision.denied

    def test_no_data_deletion_allows_normal_commands(self) -> None:
        policy = load_builtin("no-data-deletion")
        action = Action(kind="shell_command", params={"command": "ls -la"})
        decision = policy.evaluate(action)
        assert decision.allowed

    def test_all_builtins_have_severity(self) -> None:
        for policy in load_all_builtins():
            for rule in policy.rules:
                assert rule.severity is not None
