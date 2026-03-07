"""Tests for policy auto-discovery (private policies)."""

from __future__ import annotations

import textwrap
from pathlib import Path
from typing import TYPE_CHECKING

from agentguard.policies.models import Policy

if TYPE_CHECKING:
    import pytest

SAMPLE_POLICY_YAML = textwrap.dedent("""\
    name: custom-no-rm
    description: Block rm commands
    rules:
      - action: shell_command
        deny:
          - pattern: '\\brm\\b'
        severity: high
""")

SAMPLE_POLICY_2_YAML = textwrap.dedent("""\
    name: custom-no-curl
    description: Block curl commands
    rules:
      - action: shell_command
        deny:
          - pattern: '\\bcurl\\b'
        severity: medium
""")


def _write_policy(directory: Path, filename: str, content: str) -> Path:
    """Write a policy YAML file into a directory."""
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / filename
    path.write_text(content, encoding="utf-8")
    return path


class TestDiscoverPolicyDirs:
    """Test discover_policy_dirs() — finds directories to search."""

    def test_returns_empty_when_nothing_exists(self, tmp_path: Path) -> None:
        from agentguard.policies.discovery import discover_policy_dirs

        dirs = discover_policy_dirs(
            project_dir=tmp_path / "nonexistent",
            user_dir=tmp_path / "also-nonexistent",
        )
        assert dirs == []

    def test_finds_project_level_dir(self, tmp_path: Path) -> None:
        from agentguard.policies.discovery import discover_policy_dirs

        project_policies = tmp_path / ".agentguard" / "policies"
        project_policies.mkdir(parents=True)

        dirs = discover_policy_dirs(
            project_dir=project_policies,
            user_dir=tmp_path / "nonexistent",
        )
        assert dirs == [project_policies]

    def test_finds_user_level_dir(self, tmp_path: Path) -> None:
        from agentguard.policies.discovery import discover_policy_dirs

        user_policies = tmp_path / ".agentguard" / "policies"
        user_policies.mkdir(parents=True)

        dirs = discover_policy_dirs(
            project_dir=tmp_path / "nonexistent",
            user_dir=user_policies,
        )
        assert dirs == [user_policies]

    def test_finds_both_project_and_user(self, tmp_path: Path) -> None:
        from agentguard.policies.discovery import discover_policy_dirs

        project_policies = tmp_path / "project" / ".agentguard" / "policies"
        project_policies.mkdir(parents=True)
        user_policies = tmp_path / "home" / ".agentguard" / "policies"
        user_policies.mkdir(parents=True)

        dirs = discover_policy_dirs(
            project_dir=project_policies,
            user_dir=user_policies,
        )
        # Project comes before user (higher priority)
        assert dirs == [project_policies, user_policies]

    def test_env_var_dirs_come_first(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from agentguard.policies.discovery import discover_policy_dirs

        env_dir = tmp_path / "env-policies"
        env_dir.mkdir(parents=True)
        project_policies = tmp_path / "project" / ".agentguard" / "policies"
        project_policies.mkdir(parents=True)

        monkeypatch.setenv("AGENTGUARD_POLICY_DIR", str(env_dir))

        dirs = discover_policy_dirs(
            project_dir=project_policies,
            user_dir=tmp_path / "nonexistent",
        )
        assert dirs == [env_dir, project_policies]

    def test_env_var_multiple_dirs_colon_separated(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from agentguard.policies.discovery import discover_policy_dirs

        dir1 = tmp_path / "policies-a"
        dir1.mkdir()
        dir2 = tmp_path / "policies-b"
        dir2.mkdir()

        monkeypatch.setenv("AGENTGUARD_POLICY_DIR", f"{dir1}:{dir2}")

        dirs = discover_policy_dirs(
            project_dir=tmp_path / "nonexistent",
            user_dir=tmp_path / "also-nonexistent",
        )
        assert dirs == [dir1, dir2]

    def test_env_var_skips_nonexistent_dirs(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from agentguard.policies.discovery import discover_policy_dirs

        real_dir = tmp_path / "real"
        real_dir.mkdir()
        fake_dir = tmp_path / "fake"

        monkeypatch.setenv("AGENTGUARD_POLICY_DIR", f"{real_dir}:{fake_dir}")

        dirs = discover_policy_dirs(
            project_dir=tmp_path / "nonexistent",
            user_dir=tmp_path / "also-nonexistent",
        )
        assert dirs == [real_dir]

    def test_no_duplicates(self, tmp_path: Path) -> None:
        from agentguard.policies.discovery import discover_policy_dirs

        same_dir = tmp_path / ".agentguard" / "policies"
        same_dir.mkdir(parents=True)

        dirs = discover_policy_dirs(
            project_dir=same_dir,
            user_dir=same_dir,
        )
        assert dirs == [same_dir]


class TestDiscoverPolicies:
    """Test discover_policies() — loads Policy objects from auto-discovered dirs."""

    def test_returns_empty_when_no_dirs_exist(self, tmp_path: Path) -> None:
        from agentguard.policies.discovery import discover_policies

        policies = discover_policies(
            project_dir=tmp_path / "nonexistent",
            user_dir=tmp_path / "also-nonexistent",
        )
        assert policies == []

    def test_loads_policy_from_project_dir(self, tmp_path: Path) -> None:
        from agentguard.policies.discovery import discover_policies

        project_policies = tmp_path / ".agentguard" / "policies"
        _write_policy(project_policies, "custom-no-rm.yaml", SAMPLE_POLICY_YAML)

        policies = discover_policies(
            project_dir=project_policies,
            user_dir=tmp_path / "nonexistent",
        )
        assert len(policies) == 1
        assert policies[0].name == "custom-no-rm"
        assert isinstance(policies[0], Policy)

    def test_loads_policy_from_user_dir(self, tmp_path: Path) -> None:
        from agentguard.policies.discovery import discover_policies

        user_policies = tmp_path / ".agentguard" / "policies"
        _write_policy(user_policies, "custom-no-curl.yaml", SAMPLE_POLICY_2_YAML)

        policies = discover_policies(
            project_dir=tmp_path / "nonexistent",
            user_dir=user_policies,
        )
        assert len(policies) == 1
        assert policies[0].name == "custom-no-curl"

    def test_loads_from_multiple_dirs(self, tmp_path: Path) -> None:
        from agentguard.policies.discovery import discover_policies

        project_dir = tmp_path / "project" / ".agentguard" / "policies"
        user_dir = tmp_path / "home" / ".agentguard" / "policies"
        _write_policy(project_dir, "custom-no-rm.yaml", SAMPLE_POLICY_YAML)
        _write_policy(user_dir, "custom-no-curl.yaml", SAMPLE_POLICY_2_YAML)

        policies = discover_policies(
            project_dir=project_dir,
            user_dir=user_dir,
        )
        assert len(policies) == 2
        names = [p.name for p in policies]
        assert "custom-no-rm" in names
        assert "custom-no-curl" in names

    def test_deduplicates_by_name_first_wins(self, tmp_path: Path) -> None:
        """If same policy name appears in project and user dir, project wins."""
        from agentguard.policies.discovery import discover_policies

        project_dir = tmp_path / "project" / ".agentguard" / "policies"
        user_dir = tmp_path / "home" / ".agentguard" / "policies"

        # Same policy name in both dirs, different descriptions
        project_yaml = SAMPLE_POLICY_YAML.replace(
            "Block rm commands", "Project version"
        )
        user_yaml = SAMPLE_POLICY_YAML.replace("Block rm commands", "User version")

        _write_policy(project_dir, "custom-no-rm.yaml", project_yaml)
        _write_policy(user_dir, "custom-no-rm.yaml", user_yaml)

        policies = discover_policies(
            project_dir=project_dir,
            user_dir=user_dir,
        )
        assert len(policies) == 1
        assert policies[0].name == "custom-no-rm"
        assert policies[0].description == "Project version"

    def test_env_var_policies_take_highest_priority(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from agentguard.policies.discovery import discover_policies

        env_dir = tmp_path / "env-policies"
        project_dir = tmp_path / "project" / ".agentguard" / "policies"

        env_yaml = SAMPLE_POLICY_YAML.replace("Block rm commands", "Env version")
        project_yaml = SAMPLE_POLICY_YAML.replace(
            "Block rm commands", "Project version"
        )

        _write_policy(env_dir, "custom-no-rm.yaml", env_yaml)
        _write_policy(project_dir, "custom-no-rm.yaml", project_yaml)

        monkeypatch.setenv("AGENTGUARD_POLICY_DIR", str(env_dir))

        policies = discover_policies(
            project_dir=project_dir,
            user_dir=tmp_path / "nonexistent",
        )
        assert len(policies) == 1
        assert policies[0].description == "Env version"

    def test_skips_non_yaml_files(self, tmp_path: Path) -> None:
        from agentguard.policies.discovery import discover_policies

        project_dir = tmp_path / ".agentguard" / "policies"
        project_dir.mkdir(parents=True)
        _write_policy(project_dir, "custom-no-rm.yaml", SAMPLE_POLICY_YAML)
        (project_dir / "README.md").write_text("not a policy", encoding="utf-8")
        (project_dir / "notes.txt").write_text("also not a policy", encoding="utf-8")

        policies = discover_policies(
            project_dir=project_dir,
            user_dir=tmp_path / "nonexistent",
        )
        assert len(policies) == 1
        assert policies[0].name == "custom-no-rm"

    def test_skips_invalid_yaml_with_warning(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        import logging

        from agentguard.policies.discovery import discover_policies

        project_dir = tmp_path / ".agentguard" / "policies"
        _write_policy(project_dir, "valid.yaml", SAMPLE_POLICY_YAML)
        _write_policy(project_dir, "invalid.yaml", "not: a: valid: policy:")

        with caplog.at_level(logging.WARNING, logger="agentguard.policies.discovery"):
            policies = discover_policies(
                project_dir=project_dir,
                user_dir=tmp_path / "nonexistent",
            )

        # Valid policy loaded, invalid skipped
        assert len(policies) == 1
        assert policies[0].name == "custom-no-rm"
        # Warning logged for the invalid one
        assert any("invalid.yaml" in record.message for record in caplog.records)

    def test_sorted_by_filename_within_dir(self, tmp_path: Path) -> None:
        from agentguard.policies.discovery import discover_policies

        project_dir = tmp_path / ".agentguard" / "policies"
        _write_policy(project_dir, "z-policy.yaml", SAMPLE_POLICY_2_YAML)
        _write_policy(project_dir, "a-policy.yaml", SAMPLE_POLICY_YAML)

        policies = discover_policies(
            project_dir=project_dir,
            user_dir=tmp_path / "nonexistent",
        )
        assert len(policies) == 2
        # Sorted alphabetically by filename
        assert policies[0].name == "custom-no-rm"  # a-policy.yaml
        assert policies[1].name == "custom-no-curl"  # z-policy.yaml


class TestDefaultPaths:
    """Test that default_project_dir() and default_user_dir() return correct paths."""

    def test_default_project_dir_relative_to_cwd(self) -> None:
        from agentguard.policies.discovery import default_project_dir

        result = default_project_dir()
        assert result == Path.cwd() / ".agentguard" / "policies"

    def test_default_user_dir_in_home(self) -> None:
        from agentguard.policies.discovery import default_user_dir

        result = default_user_dir()
        assert result == Path.home() / ".agentguard" / "policies"


class TestDiscoverPoliciesConvenience:
    """Test the convenience function that uses default paths."""

    def test_auto_discover_uses_defaults(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Ensure auto_discover() calls discover_policies with default paths."""
        from agentguard.policies.discovery import auto_discover

        # Set CWD to tmp_path so the project dir is predictable
        monkeypatch.chdir(tmp_path)
        # Remove env var to avoid interference
        monkeypatch.delenv("AGENTGUARD_POLICY_DIR", raising=False)

        project_dir = tmp_path / ".agentguard" / "policies"
        _write_policy(project_dir, "custom-no-rm.yaml", SAMPLE_POLICY_YAML)

        policies = auto_discover()
        assert len(policies) == 1
        assert policies[0].name == "custom-no-rm"
