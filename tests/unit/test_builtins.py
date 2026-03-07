"""Tests for built-in policies (M1.4)."""

from __future__ import annotations

import pytest

from agentguard.policies.builtins import (
    list_builtins,
    load_all_builtins,
    load_builtin,
)
from agentguard.policies.models import Action, Policy, Severity


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
        assert "no-hook-bypass" in names
        assert "no-env-commit" in names


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

    def test_load_no_hook_bypass(self) -> None:
        policy = load_builtin("no-hook-bypass")
        assert isinstance(policy, Policy)
        assert policy.name == "no-hook-bypass"

    def test_load_no_env_commit(self) -> None:
        policy = load_builtin("no-env-commit")
        assert isinstance(policy, Policy)
        assert policy.name == "no-env-commit"

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
        assert "no-hook-bypass" in names
        assert "no-env-commit" in names


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

    # -- no-secret-exposure: expanded patterns --

    def test_no_secret_exposure_blocks_github_pat_classic(self) -> None:
        policy = load_builtin("no-secret-exposure")
        action = Action(
            kind="file_write",
            params={
                "path": "config.txt",
                "content": "ghp_" + "a" * 36,
            },
        )
        decision = policy.evaluate(action)
        assert decision.denied

    def test_no_secret_exposure_blocks_github_pat_fine_grained(self) -> None:
        policy = load_builtin("no-secret-exposure")
        action = Action(
            kind="file_write",
            params={
                "path": "config.txt",
                "content": "github_pat_" + "A" * 22,
            },
        )
        decision = policy.evaluate(action)
        assert decision.denied

    def test_no_secret_exposure_blocks_aws_access_key(self) -> None:
        policy = load_builtin("no-secret-exposure")
        action = Action(
            kind="file_write",
            params={
                "path": "deploy.sh",
                "content": "AKIAIOSFODNN7EXAMPLE",
            },
        )
        decision = policy.evaluate(action)
        assert decision.denied

    def test_no_secret_exposure_blocks_slack_webhook(self) -> None:
        policy = load_builtin("no-secret-exposure")
        # Build URL dynamically to avoid GitHub push protection
        slack_url = "hooks.slack" + ".com/services/T0/B0/X"
        action = Action(
            kind="file_write",
            params={"path": "notify.py", "content": slack_url},
        )
        decision = policy.evaluate(action)
        assert decision.denied

    def test_no_secret_exposure_blocks_discord_webhook(self) -> None:
        policy = load_builtin("no-secret-exposure")
        # Build URL dynamically to avoid GitHub push protection
        discord_url = "discord" + ".com/api/webhooks/123/abc"
        action = Action(
            kind="file_write",
            params={
                "path": "bot.py",
                "content": discord_url,
            },
        )
        decision = policy.evaluate(action)
        assert decision.denied

    def test_no_secret_exposure_blocks_bearer_token(self) -> None:
        policy = load_builtin("no-secret-exposure")
        action = Action(
            kind="file_write",
            params={
                "path": "api.py",
                "content": "Bearer eyJhbGciOiJIUzI1NiIs",
            },
        )
        decision = policy.evaluate(action)
        assert decision.denied

    def test_no_secret_exposure_blocks_db_connection_string(self) -> None:
        policy = load_builtin("no-secret-exposure")
        action = Action(
            kind="file_write",
            params={
                "path": "db.py",
                "content": "dsn = 'postgresql://admin:s3cret@db.example.com:5432/production'",
            },
        )
        decision = policy.evaluate(action)
        assert decision.denied

    def test_no_secret_exposure_allows_db_url_without_password(self) -> None:
        policy = load_builtin("no-secret-exposure")
        action = Action(
            kind="file_write",
            params={
                "path": "db.py",
                "content": "dsn = 'postgresql://localhost:5432/testdb'",
            },
        )
        decision = policy.evaluate(action)
        assert decision.allowed

    def test_no_secret_exposure_blocks_pem_file(self) -> None:
        policy = load_builtin("no-secret-exposure")
        action = Action(
            kind="file_write",
            params={"path": "/etc/ssl/private/server.pem"},
        )
        decision = policy.evaluate(action)
        assert decision.denied

    def test_no_secret_exposure_blocks_keystore(self) -> None:
        policy = load_builtin("no-secret-exposure")
        action = Action(kind="file_write", params={"path": "release.keystore"})
        decision = policy.evaluate(action)
        assert decision.denied

    def test_no_secret_exposure_blocks_p12_file(self) -> None:
        policy = load_builtin("no-secret-exposure")
        action = Action(kind="file_write", params={"path": "cert.p12"})
        decision = policy.evaluate(action)
        assert decision.denied

    # -- no-hook-bypass: new policy --

    def test_no_hook_bypass_blocks_no_verify(self) -> None:
        policy = load_builtin("no-hook-bypass")
        action = Action(
            kind="shell_command",
            params={"command": "git commit --no-verify -m 'skip hooks'"},
        )
        decision = policy.evaluate(action)
        assert decision.denied

    def test_no_hook_bypass_blocks_commit_n_shorthand(self) -> None:
        policy = load_builtin("no-hook-bypass")
        action = Action(
            kind="shell_command",
            params={"command": "git commit -n -m 'skip hooks'"},
        )
        decision = policy.evaluate(action)
        assert decision.denied

    def test_no_hook_bypass_blocks_push_no_verify(self) -> None:
        policy = load_builtin("no-hook-bypass")
        action = Action(
            kind="shell_command",
            params={"command": "git push --no-verify origin main"},
        )
        decision = policy.evaluate(action)
        assert decision.denied

    def test_no_hook_bypass_blocks_merge_no_verify(self) -> None:
        policy = load_builtin("no-hook-bypass")
        action = Action(
            kind="shell_command",
            params={"command": "git merge --no-verify feature-branch"},
        )
        decision = policy.evaluate(action)
        assert decision.denied

    def test_no_hook_bypass_allows_normal_commit(self) -> None:
        policy = load_builtin("no-hook-bypass")
        action = Action(
            kind="shell_command",
            params={"command": "git commit -m 'normal commit'"},
        )
        decision = policy.evaluate(action)
        assert decision.allowed

    def test_no_hook_bypass_allows_normal_push(self) -> None:
        policy = load_builtin("no-hook-bypass")
        action = Action(
            kind="shell_command",
            params={"command": "git push origin main"},
        )
        decision = policy.evaluate(action)
        assert decision.allowed

    def test_no_hook_bypass_blocks_commit_nm_combined_flags(self) -> None:
        """git commit -nm 'msg' combines -n and -m into one flag group."""
        policy = load_builtin("no-hook-bypass")
        action = Action(
            kind="shell_command",
            params={"command": "git commit -nm 'skip hooks'"},
        )
        decision = policy.evaluate(action)
        assert decision.denied

    def test_no_hook_bypass_blocks_commit_amend_n(self) -> None:
        """git commit --amend -n at end of command (no trailing space)."""
        policy = load_builtin("no-hook-bypass")
        action = Action(
            kind="shell_command",
            params={"command": "git commit --amend -n"},
        )
        decision = policy.evaluate(action)
        assert decision.denied

    def test_no_hook_bypass_blocks_n_at_end_of_command(self) -> None:
        """git commit -n at end of string with no trailing space."""
        policy = load_builtin("no-hook-bypass")
        action = Action(
            kind="shell_command",
            params={"command": "git commit -n"},
        )
        decision = policy.evaluate(action)
        assert decision.denied

    def test_no_hook_bypass_does_not_false_positive_on_n_in_message(self) -> None:
        """Ensure -n inside a commit message doesn't trigger false positive."""
        policy = load_builtin("no-hook-bypass")
        action = Action(
            kind="shell_command",
            params={"command": "git commit -m 'not-n-flag'"},
        )
        decision = policy.evaluate(action)
        assert decision.allowed

    def test_no_hook_bypass_blocks_no_verify_with_global_options(self) -> None:
        """git -C repo commit --no-verify should be blocked."""
        policy = load_builtin("no-hook-bypass")
        action = Action(
            kind="shell_command",
            params={"command": "git -C repo commit --no-verify -m 'x'"},
        )
        decision = policy.evaluate(action)
        assert decision.denied

    def test_no_hook_bypass_blocks_no_verify_with_git_dir(self) -> None:
        """git --git-dir=.git commit --no-verify should be blocked."""
        policy = load_builtin("no-hook-bypass")
        action = Action(
            kind="shell_command",
            params={"command": "git --git-dir=.git commit --no-verify"},
        )
        decision = policy.evaluate(action)
        assert decision.denied

    def test_no_hook_bypass_severity_is_high(self) -> None:
        policy = load_builtin("no-hook-bypass")
        assert policy.rules[0].severity == Severity.HIGH

    # -- no-env-commit: new policy --

    def test_no_env_commit_blocks_git_add_env(self) -> None:
        policy = load_builtin("no-env-commit")
        action = Action(
            kind="shell_command",
            params={"command": "git add .env"},
        )
        decision = policy.evaluate(action)
        assert decision.denied

    def test_no_env_commit_blocks_git_add_env_local(self) -> None:
        policy = load_builtin("no-env-commit")
        action = Action(
            kind="shell_command",
            params={"command": "git add .env.local"},
        )
        decision = policy.evaluate(action)
        assert decision.denied

    def test_no_env_commit_blocks_git_add_env_production(self) -> None:
        policy = load_builtin("no-env-commit")
        action = Action(
            kind="shell_command",
            params={"command": "git add .env.production"},
        )
        decision = policy.evaluate(action)
        assert decision.denied

    def test_no_env_commit_allows_git_add_env_example(self) -> None:
        policy = load_builtin("no-env-commit")
        action = Action(
            kind="shell_command",
            params={"command": "git add .env.example"},
        )
        decision = policy.evaluate(action)
        assert decision.allowed

    def test_no_env_commit_blocks_git_add_pem_file(self) -> None:
        policy = load_builtin("no-env-commit")
        action = Action(
            kind="shell_command",
            params={"command": "git add server.pem"},
        )
        decision = policy.evaluate(action)
        assert decision.denied

    def test_no_env_commit_blocks_git_add_private_key(self) -> None:
        policy = load_builtin("no-env-commit")
        action = Action(
            kind="shell_command",
            params={"command": "git add id_rsa"},
        )
        decision = policy.evaluate(action)
        assert decision.denied

    def test_no_env_commit_blocks_git_add_keystore(self) -> None:
        policy = load_builtin("no-env-commit")
        action = Action(
            kind="shell_command",
            params={"command": "git add release.keystore"},
        )
        decision = policy.evaluate(action)
        assert decision.denied

    def test_no_env_commit_blocks_git_add_credentials_json(self) -> None:
        policy = load_builtin("no-env-commit")
        action = Action(
            kind="shell_command",
            params={"command": "git add credentials.json"},
        )
        decision = policy.evaluate(action)
        assert decision.denied

    def test_no_env_commit_allows_normal_git_add(self) -> None:
        policy = load_builtin("no-env-commit")
        action = Action(
            kind="shell_command",
            params={"command": "git add src/main.py"},
        )
        decision = policy.evaluate(action)
        assert decision.allowed

    def test_no_env_commit_allows_non_git_commands(self) -> None:
        policy = load_builtin("no-env-commit")
        action = Action(
            kind="shell_command",
            params={"command": "cat .env"},
        )
        decision = policy.evaluate(action)
        assert decision.allowed

    def test_no_env_commit_blocks_path_prefixed_env(self) -> None:
        """git add path/to/.env should be blocked."""
        policy = load_builtin("no-env-commit")
        action = Action(
            kind="shell_command",
            params={"command": "git add config/.env"},
        )
        decision = policy.evaluate(action)
        assert decision.denied

    def test_no_env_commit_blocks_env_at_end_of_string(self) -> None:
        """git add .env at end-of-string (no trailing chars)."""
        policy = load_builtin("no-env-commit")
        action = Action(
            kind="shell_command",
            params={"command": "git add .env"},
        )
        decision = policy.evaluate(action)
        assert decision.denied

    def test_no_env_commit_allows_env_example_with_path(self) -> None:
        """git add config/.env.example should be allowed."""
        policy = load_builtin("no-env-commit")
        action = Action(
            kind="shell_command",
            params={"command": "git add config/.env.example"},
        )
        decision = policy.evaluate(action)
        assert decision.allowed

    def test_no_env_commit_blocks_git_add_double_dash_env(self) -> None:
        """git add -- .env should be blocked."""
        policy = load_builtin("no-env-commit")
        action = Action(
            kind="shell_command",
            params={"command": "git add -- .env"},
        )
        decision = policy.evaluate(action)
        assert decision.denied

    def test_no_env_commit_blocks_git_add_with_options(self) -> None:
        """git add -A .env should be blocked."""
        policy = load_builtin("no-env-commit")
        action = Action(
            kind="shell_command",
            params={"command": "git add -A .env"},
        )
        decision = policy.evaluate(action)
        assert decision.denied

    def test_no_env_commit_severity_is_critical(self) -> None:
        policy = load_builtin("no-env-commit")
        for rule in policy.rules:
            assert rule.severity == Severity.CRITICAL

    def test_all_builtins_have_severity(self) -> None:
        for policy in load_all_builtins():
            for rule in policy.rules:
                assert rule.severity is not None
