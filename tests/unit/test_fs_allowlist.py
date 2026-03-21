"""Tests for filesystem allowlist policy type (M12).

Covers:
- FilesystemAllowlist creation and configuration
- Exact path matching
- Directory prefix matching (everything under a dir)
- Glob pattern matching
- Preset loading (temp, project, etc.)
- Deny for unlisted paths
- Allow for listed paths
- Path normalization
- Guard integration
- YAML loading of fs_allowlist policies
"""

from __future__ import annotations

import os

import pytest

from agentguard.policies.fs_allowlist import (
    FS_PRESETS,
    FilesystemAllowlist,
)
from agentguard.policies.guard import Guard
from agentguard.policies.loader import load_policy_from_string

# --- FilesystemAllowlist creation ---


class TestFilesystemAllowlistCreation:
    """Tests for FilesystemAllowlist initialization."""

    def test_create_with_paths(self) -> None:
        al = FilesystemAllowlist(
            name="test",
            allowed_paths=["/home/user/project/"],
        )
        assert al.name == "test"

    def test_create_with_preset(self) -> None:
        al = FilesystemAllowlist(
            name="test",
            presets=["temp"],
        )
        assert al.name == "test"

    def test_empty_paths_and_presets_raises(self) -> None:
        with pytest.raises(ValueError, match=r"allowed_paths.*presets"):
            FilesystemAllowlist(name="test")

    def test_unknown_preset_raises(self) -> None:
        with pytest.raises(ValueError, match="unknown_preset"):
            FilesystemAllowlist(name="test", presets=["unknown_preset"])

    def test_bare_glob_pattern_raises(self) -> None:
        """Bare glob patterns without directory anchor are rejected."""
        with pytest.raises(ValueError, match=r"Bare glob pattern.*not allowed"):
            FilesystemAllowlist(name="test", allowed_paths=["*.py"])


# --- Path matching ---


class TestPathMatching:
    """Tests for filesystem allowlist path matching."""

    def test_exact_path_allowed(self) -> None:
        al = FilesystemAllowlist(
            name="test",
            allowed_paths=["/home/user/config.yaml"],
        )
        decision = al.evaluate_path("/home/user/config.yaml")
        assert decision.allowed is True

    def test_unlisted_path_denied(self) -> None:
        al = FilesystemAllowlist(
            name="test",
            allowed_paths=["/home/user/project/"],
        )
        decision = al.evaluate_path("/etc/passwd")
        assert decision.denied is True
        assert decision.denied_by == "test"

    def test_directory_prefix_allows_children(self) -> None:
        """Paths ending with '/' allow all files underneath."""
        al = FilesystemAllowlist(
            name="test",
            allowed_paths=["/home/user/project/"],
        )
        assert al.evaluate_path("/home/user/project/src/main.py").allowed is True
        assert al.evaluate_path("/home/user/project/README.md").allowed is True

    def test_directory_prefix_must_be_exact(self) -> None:
        """'/home/user/project/' should not match '/home/user/project2/x'."""
        al = FilesystemAllowlist(
            name="test",
            allowed_paths=["/home/user/project/"],
        )
        decision = al.evaluate_path("/home/user/project2/file.py")
        assert decision.denied is True

    def test_glob_pattern_matching(self) -> None:
        al = FilesystemAllowlist(
            name="test",
            allowed_paths=["/home/user/project/*.py"],
        )
        assert al.evaluate_path("/home/user/project/main.py").allowed is True
        assert al.evaluate_path("/home/user/project/test.py").allowed is True
        assert al.evaluate_path("/home/user/project/data.csv").denied is True

    def test_anchored_glob_does_not_match_other_dirs(self) -> None:
        """'/home/user/project/*.py' must not match '/etc/evil.py'."""
        al = FilesystemAllowlist(
            name="test",
            allowed_paths=["/home/user/project/*.py"],
        )
        assert al.evaluate_path("/etc/evil.py").denied is True
        assert al.evaluate_path("/root/.ssh/keys.py").denied is True

    def test_recursive_glob(self) -> None:
        al = FilesystemAllowlist(
            name="test",
            allowed_paths=["/home/user/project/**/*.py"],
        )
        assert al.evaluate_path("/home/user/project/src/main.py").allowed is True
        assert al.evaluate_path("/home/user/project/tests/test_main.py").allowed is True

    def test_path_normalization(self) -> None:
        """Paths with '..' and '.' should be normalized."""
        al = FilesystemAllowlist(
            name="test",
            allowed_paths=["/home/user/project/"],
        )
        decision = al.evaluate_path("/home/user/project/src/../src/main.py")
        assert decision.allowed is True

    def test_multiple_allowed_paths(self) -> None:
        al = FilesystemAllowlist(
            name="test",
            allowed_paths=[
                "/home/user/project/",
                "/tmp/",
                "/home/user/.config/app.yaml",
            ],
        )
        assert al.evaluate_path("/home/user/project/src/main.py").allowed is True
        assert al.evaluate_path("/tmp/test.txt").allowed is True
        assert al.evaluate_path("/home/user/.config/app.yaml").allowed is True
        assert al.evaluate_path("/etc/shadow").denied is True

    def test_relative_path_denied(self) -> None:
        """Relative paths that escape allowed dirs should be denied."""
        al = FilesystemAllowlist(
            name="test",
            allowed_paths=["/home/user/project/"],
        )
        # Traversal attempt
        decision = al.evaluate_path("/home/user/project/../../etc/passwd")
        assert decision.denied is True


# --- Presets ---


class TestPresets:
    """Tests for built-in filesystem presets."""

    def test_temp_preset_exists(self) -> None:
        assert "temp" in FS_PRESETS

    def test_project_preset_exists(self) -> None:
        assert "project" in FS_PRESETS

    def test_project_preset_allows_cwd_files(self) -> None:
        """Project preset resolves ./ to CWD and allows files under it."""
        al = FilesystemAllowlist(name="test", presets=["project"])
        cwd = os.getcwd()
        assert al.evaluate_path(cwd + "/file.py").allowed is True
        assert al.evaluate_path(cwd + "/src/main.py").allowed is True
        assert al.evaluate_path("/etc/passwd").denied is True

    def test_preset_paths_are_lists(self) -> None:
        for name, paths in FS_PRESETS.items():
            assert isinstance(paths, list), f"Preset '{name}' is not a list"
            assert len(paths) > 0, f"Preset '{name}' is empty"

    def test_temp_preset_includes_tmp(self) -> None:
        al = FilesystemAllowlist(name="test", presets=["temp"])
        assert al.evaluate_path("/tmp/test.txt").allowed is True

    def test_combined_presets_and_paths(self) -> None:
        al = FilesystemAllowlist(
            name="test",
            allowed_paths=["/custom/dir/"],
            presets=["temp"],
        )
        assert al.evaluate_path("/tmp/test.txt").allowed is True
        assert al.evaluate_path("/custom/dir/file.py").allowed is True
        assert al.evaluate_path("/etc/shadow").denied is True


# --- Guard integration ---


class TestGuardIntegration:
    """Tests for FilesystemAllowlist as a Policy in Guard."""

    def test_fs_policy_in_guard_with_path_param(self) -> None:
        al = FilesystemAllowlist(
            name="fs-guard",
            allowed_paths=["/home/user/project/"],
            action_kind="file_write",
        )
        guard = Guard(policies=[al])

        decision = guard.check("file_write", path="/home/user/project/output.txt")
        assert decision.allowed is True

        decision = guard.check("file_write", path="/etc/passwd")
        assert decision.denied is True

    def test_fs_policy_with_file_param(self) -> None:
        al = FilesystemAllowlist(
            name="fs-guard",
            allowed_paths=["/home/user/project/"],
            action_kind="file_read",
        )
        guard = Guard(policies=[al])

        decision = guard.check("file_read", file="/home/user/project/data.csv")
        assert decision.allowed is True

    def test_non_matching_action_kind_passes(self) -> None:
        al = FilesystemAllowlist(
            name="fs-guard",
            allowed_paths=["/home/user/project/"],
            action_kind="file_write",
        )
        guard = Guard(policies=[al])

        decision = guard.check("shell_command", command="echo hello")
        assert decision.allowed is True

    def test_action_without_path_denied(self) -> None:
        al = FilesystemAllowlist(
            name="fs-guard",
            allowed_paths=["/home/user/project/"],
            action_kind="file_write",
        )
        guard = Guard(policies=[al])

        decision = guard.check("file_write", content="data")
        assert decision.denied is True


# --- YAML loading ---


class TestYAMLLoading:
    """Tests for loading filesystem allowlist from YAML."""

    def test_load_fs_allowlist_from_yaml(self) -> None:
        yaml_str = """
name: file-access
type: fs_allowlist
action: file_write
paths:
  - /home/user/project/
  - /tmp/
"""
        policy = load_policy_from_string(yaml_str)
        assert isinstance(policy, FilesystemAllowlist)
        assert policy.name == "file-access"

    def test_load_with_presets(self) -> None:
        yaml_str = """
name: with-presets
type: fs_allowlist
action: file_write
presets:
  - temp
"""
        policy = load_policy_from_string(yaml_str)
        assert isinstance(policy, FilesystemAllowlist)

    def test_yaml_fs_allowlist_in_guard(self) -> None:
        yaml_str = """
name: file-guard
type: fs_allowlist
action: file_write
paths:
  - /safe/dir/
"""
        guard = Guard()
        guard.load_policy_string(yaml_str)

        decision = guard.check("file_write", path="/safe/dir/output.txt")
        assert decision.allowed is True

        decision = guard.check("file_write", path="/etc/shadow")
        assert decision.denied is True
