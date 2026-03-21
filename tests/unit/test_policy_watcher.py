"""Tests for hot-reload policy file watcher (M12).

Covers:
- PolicyWatcher creation and configuration
- File change detection via mtime polling
- Policy reload on file change
- Multiple file watching
- New file detection
- File deletion handling
- Callback on reload
- Thread start/stop lifecycle
- Context manager usage
- Error handling on reload (bad YAML)
- Guard integration after reload
"""

from __future__ import annotations

import time
from typing import TYPE_CHECKING
from unittest.mock import MagicMock

from agentguard.policies.guard import Guard
from agentguard.policies.watcher import PolicyWatcher

if TYPE_CHECKING:
    from pathlib import Path


def _write_policy(path: Path, name: str, pattern: str = "rm -rf") -> None:
    """Write a simple deny policy YAML file."""
    path.write_text(
        f"""\
name: {name}
rules:
  - action: shell_command
    severity: critical
    deny:
      - pattern: '{pattern}'
""",
        encoding="utf-8",
    )


# --- PolicyWatcher creation ---


class TestPolicyWatcherCreation:
    """Tests for PolicyWatcher initialization."""

    def test_create_watcher_with_guard(self, tmp_path: Path) -> None:
        guard = Guard()
        watcher = PolicyWatcher(guard=guard, paths=[tmp_path])
        assert watcher.guard is guard
        assert watcher.poll_interval == 2.0

    def test_custom_poll_interval(self, tmp_path: Path) -> None:
        guard = Guard()
        watcher = PolicyWatcher(
            guard=guard,
            paths=[tmp_path],
            poll_interval=0.5,
        )
        assert watcher.poll_interval == 0.5

    def test_create_with_file_paths(self, tmp_path: Path) -> None:
        policy_file = tmp_path / "policy.yaml"
        _write_policy(policy_file, "test")
        guard = Guard()
        watcher = PolicyWatcher(guard=guard, paths=[policy_file])
        assert len(watcher.paths) == 1

    def test_create_with_directory_path(self, tmp_path: Path) -> None:
        _write_policy(tmp_path / "p1.yaml", "p1")
        _write_policy(tmp_path / "p2.yaml", "p2")
        guard = Guard()
        watcher = PolicyWatcher(guard=guard, paths=[tmp_path])
        assert len(watcher.paths) == 1


# --- File change detection ---


class TestFileChangeDetection:
    """Tests for detecting file changes."""

    def test_detects_file_modification(self, tmp_path: Path) -> None:
        policy_file = tmp_path / "policy.yaml"
        _write_policy(policy_file, "test", pattern="rm -rf")
        guard = Guard()
        watcher = PolicyWatcher(
            guard=guard,
            paths=[policy_file],
            poll_interval=0.1,
        )

        # Initial load
        watcher.reload()
        assert len(guard.policies) == 1
        assert guard.policies[0].name == "test"

        # Modify file
        time.sleep(0.05)  # Ensure mtime changes
        _write_policy(policy_file, "test-updated", pattern="DROP TABLE")

        assert watcher.has_changes()

    def test_no_changes_when_unmodified(self, tmp_path: Path) -> None:
        policy_file = tmp_path / "policy.yaml"
        _write_policy(policy_file, "test")
        guard = Guard()
        watcher = PolicyWatcher(
            guard=guard,
            paths=[policy_file],
            poll_interval=0.1,
        )
        watcher.reload()

        assert not watcher.has_changes()


# --- Policy reload ---


class TestPolicyReload:
    """Tests for policy reloading."""

    def test_reload_replaces_policies(self, tmp_path: Path) -> None:
        policy_file = tmp_path / "policy.yaml"
        _write_policy(policy_file, "v1", pattern="rm -rf")
        guard = Guard()
        watcher = PolicyWatcher(
            guard=guard,
            paths=[policy_file],
            poll_interval=0.1,
        )
        watcher.reload()

        decision = guard.check("shell_command", command="rm -rf /")
        assert decision.denied is True

        # Update policy
        _write_policy(policy_file, "v2", pattern="DROP TABLE")
        watcher.reload()

        # Old pattern no longer denied
        decision = guard.check("shell_command", command="rm -rf /")
        assert decision.allowed is True

        # New pattern denied
        decision = guard.check("shell_command", command="DROP TABLE users")
        assert decision.denied is True

    def test_reload_multiple_files(self, tmp_path: Path) -> None:
        p1 = tmp_path / "p1.yaml"
        p2 = tmp_path / "p2.yaml"
        _write_policy(p1, "policy-1", pattern="rm -rf")
        _write_policy(p2, "policy-2", pattern="DROP TABLE")
        guard = Guard()
        watcher = PolicyWatcher(
            guard=guard,
            paths=[p1, p2],
            poll_interval=0.1,
        )
        watcher.reload()

        assert len(guard.policies) == 2
        names = {p.name for p in guard.policies}
        assert names == {"policy-1", "policy-2"}

    def test_reload_from_directory(self, tmp_path: Path) -> None:
        _write_policy(tmp_path / "a.yaml", "alpha")
        _write_policy(tmp_path / "b.yaml", "beta")
        guard = Guard()
        watcher = PolicyWatcher(
            guard=guard,
            paths=[tmp_path],
            poll_interval=0.1,
        )
        watcher.reload()

        assert len(guard.policies) == 2

    def test_reload_detects_new_file_in_directory(self, tmp_path: Path) -> None:
        _write_policy(tmp_path / "existing.yaml", "existing")
        guard = Guard()
        watcher = PolicyWatcher(
            guard=guard,
            paths=[tmp_path],
            poll_interval=0.1,
        )
        watcher.reload()
        assert len(guard.policies) == 1

        # Add a new file
        time.sleep(0.05)
        _write_policy(tmp_path / "new.yaml", "new-policy")
        watcher.reload()
        assert len(guard.policies) == 2

    def test_reload_handles_deleted_file(self, tmp_path: Path) -> None:
        p1 = tmp_path / "p1.yaml"
        p2 = tmp_path / "p2.yaml"
        _write_policy(p1, "keep")
        _write_policy(p2, "remove")
        guard = Guard()
        watcher = PolicyWatcher(
            guard=guard,
            paths=[tmp_path],
            poll_interval=0.1,
        )
        watcher.reload()
        assert len(guard.policies) == 2

        # Delete one file
        p2.unlink()
        watcher.reload()
        assert len(guard.policies) == 1
        assert guard.policies[0].name == "keep"

    def test_reload_preserves_deny_handlers(self, tmp_path: Path) -> None:
        """Deny handlers on Guard survive a policy reload."""
        policy_file = tmp_path / "policy.yaml"
        _write_policy(policy_file, "test")
        guard = Guard()
        handler = MagicMock()
        guard.on_deny(handler)

        watcher = PolicyWatcher(
            guard=guard,
            paths=[policy_file],
            poll_interval=0.1,
        )
        watcher.reload()

        decision = guard.check("shell_command", command="rm -rf /")
        assert decision.denied is True
        handler.assert_called_once()


# --- Callbacks ---


class TestReloadCallback:
    """Tests for on_reload callback."""

    def test_callback_called_on_reload(self, tmp_path: Path) -> None:
        policy_file = tmp_path / "policy.yaml"
        _write_policy(policy_file, "test")
        guard = Guard()
        callback = MagicMock()
        watcher = PolicyWatcher(
            guard=guard,
            paths=[policy_file],
            poll_interval=0.1,
            on_reload=callback,
        )
        watcher.reload()

        callback.assert_called_once()
        call_args = callback.call_args[0]
        assert isinstance(call_args[0], list)  # list of policies
        assert len(call_args[0]) == 1


# --- Thread lifecycle ---


class TestWatcherThread:
    """Tests for watcher thread start/stop."""

    def test_start_stop(self, tmp_path: Path) -> None:
        policy_file = tmp_path / "policy.yaml"
        _write_policy(policy_file, "test")
        guard = Guard()
        watcher = PolicyWatcher(
            guard=guard,
            paths=[policy_file],
            poll_interval=0.1,
        )

        watcher.start()
        assert watcher.is_running

        watcher.stop()
        assert not watcher.is_running

    def test_context_manager(self, tmp_path: Path) -> None:
        policy_file = tmp_path / "policy.yaml"
        _write_policy(policy_file, "test")
        guard = Guard()
        watcher = PolicyWatcher(
            guard=guard,
            paths=[policy_file],
            poll_interval=0.1,
        )

        with watcher:
            assert watcher.is_running
        assert not watcher.is_running

    def test_auto_reload_on_change(self, tmp_path: Path) -> None:
        """Watcher thread detects changes and reloads automatically."""
        policy_file = tmp_path / "policy.yaml"
        _write_policy(policy_file, "v1", pattern="rm -rf")
        guard = Guard()
        callback = MagicMock()
        watcher = PolicyWatcher(
            guard=guard,
            paths=[policy_file],
            poll_interval=0.1,
            on_reload=callback,
        )

        with watcher:
            # Wait for initial load
            time.sleep(0.3)
            assert len(guard.policies) == 1

            # Modify file
            _write_policy(policy_file, "v2", pattern="DROP TABLE")

            # Wait for the watcher to detect and reload
            time.sleep(0.5)

        # After stop, check that reload happened
        # The callback should have been called at least twice
        # (initial + at least one change detection)
        assert callback.call_count >= 2

    def test_double_start_is_safe(self, tmp_path: Path) -> None:
        policy_file = tmp_path / "policy.yaml"
        _write_policy(policy_file, "test")
        guard = Guard()
        watcher = PolicyWatcher(
            guard=guard,
            paths=[policy_file],
            poll_interval=0.1,
        )

        watcher.start()
        watcher.start()  # Should not raise
        assert watcher.is_running
        watcher.stop()

    def test_double_stop_is_safe(self, tmp_path: Path) -> None:
        policy_file = tmp_path / "policy.yaml"
        _write_policy(policy_file, "test")
        guard = Guard()
        watcher = PolicyWatcher(
            guard=guard,
            paths=[policy_file],
            poll_interval=0.1,
        )

        watcher.start()
        watcher.stop()
        watcher.stop()  # Should not raise
        assert not watcher.is_running


# --- Error handling ---


class TestErrorHandling:
    """Tests for error handling during reload."""

    def test_bad_yaml_does_not_crash(self, tmp_path: Path) -> None:
        """Invalid YAML should log error but not crash watcher."""
        policy_file = tmp_path / "policy.yaml"
        _write_policy(policy_file, "test")
        guard = Guard()
        watcher = PolicyWatcher(
            guard=guard,
            paths=[policy_file],
            poll_interval=0.1,
        )
        watcher.reload()
        assert len(guard.policies) == 1

        # Write invalid YAML
        policy_file.write_text("invalid: yaml: content: [", encoding="utf-8")

        # Reload should not raise; policies should remain unchanged
        watcher.reload()
        assert len(guard.policies) == 1  # Previous policies kept

    def test_missing_file_skipped(self, tmp_path: Path) -> None:
        """A file path that doesn't exist is silently skipped."""
        existing = tmp_path / "exists.yaml"
        missing = tmp_path / "missing.yaml"
        _write_policy(existing, "exists")
        guard = Guard()
        watcher = PolicyWatcher(
            guard=guard,
            paths=[existing, missing],
            poll_interval=0.1,
        )
        watcher.reload()
        assert len(guard.policies) == 1
        assert guard.policies[0].name == "exists"

    def test_non_yaml_files_in_directory_ignored(self, tmp_path: Path) -> None:
        """Only .yaml and .yml files should be loaded from directories."""
        _write_policy(tmp_path / "good.yaml", "good")
        (tmp_path / "readme.txt").write_text("not a policy", encoding="utf-8")
        (tmp_path / "config.json").write_text("{}", encoding="utf-8")
        guard = Guard()
        watcher = PolicyWatcher(
            guard=guard,
            paths=[tmp_path],
            poll_interval=0.1,
        )
        watcher.reload()
        assert len(guard.policies) == 1
        assert guard.policies[0].name == "good"
