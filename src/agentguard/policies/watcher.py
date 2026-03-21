"""Hot-reload policy file watcher.

Monitors YAML policy files for changes and automatically reloads
them into a Guard instance. Uses file stat polling (no external
dependencies).

Usage::

    from agentguard.policies.guard import Guard
    from agentguard.policies.watcher import PolicyWatcher

    guard = Guard()
    watcher = PolicyWatcher(guard=guard, paths=["policies/"])

    with watcher:
        # Watcher polls for changes in background thread.
        # Guard policies are automatically updated on file changes.
        decision = guard.check("shell_command", command="rm -rf /")
"""

from __future__ import annotations

import contextlib
import logging
import threading
from collections.abc import Callable
from pathlib import Path

from agentguard.policies.loader import load_policy_from_yaml
from agentguard.policies.models import Policy

logger = logging.getLogger(__name__)

#: File extensions treated as policy files when scanning directories.
_POLICY_EXTENSIONS = {".yaml", ".yml"}

#: Type alias for reload callback.
ReloadCallback = Callable[[list[Policy]], None]


class PolicyWatcher:
    """Watch policy files for changes and hot-reload into a Guard.

    Monitors file modification times at a configurable polling
    interval. When changes are detected, reloads all policy files
    and replaces the Guard's policy list atomically.

    Supports watching individual files and/or directories (scans
    for ``*.yaml`` and ``*.yml`` files).

    Args:
        guard: The Guard instance whose policies will be updated.
        paths: List of file or directory paths to watch.
        poll_interval: Seconds between polls (default 2.0).
        on_reload: Optional callback invoked after a successful
            reload with the new list of policies.
    """

    def __init__(
        self,
        guard: object,
        paths: list[str | Path],
        poll_interval: float = 2.0,
        on_reload: ReloadCallback | None = None,
    ) -> None:
        # Import here to avoid circular imports at module level
        from agentguard.policies.guard import Guard

        if not isinstance(guard, Guard):
            msg = "guard must be a Guard instance"
            raise TypeError(msg)

        self._guard: Guard = guard
        self._paths = [Path(p) for p in paths]
        self._poll_interval = poll_interval
        self._on_reload = on_reload
        self._mtimes: dict[Path, float] = {}
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None

    @property
    def guard(self) -> object:
        """The Guard instance being managed."""
        return self._guard

    @property
    def paths(self) -> list[Path]:
        """The watched paths."""
        return list(self._paths)

    @property
    def poll_interval(self) -> float:
        """Polling interval in seconds."""
        return self._poll_interval

    @property
    def is_running(self) -> bool:
        """Whether the watcher thread is running."""
        return self._thread is not None and self._thread.is_alive()

    def _resolve_files(self) -> list[Path]:
        """Resolve all watched paths to individual YAML files.

        Directories are scanned for ``*.yaml`` and ``*.yml`` files.
        Missing paths are silently skipped.

        Returns:
            Sorted list of existing YAML file paths.
        """
        files: list[Path] = []
        for path in self._paths:
            if path.is_dir():
                for child in sorted(path.iterdir()):
                    if child.is_file() and child.suffix in _POLICY_EXTENSIONS:
                        files.append(child)
            elif path.is_file():
                files.append(path)
            # Missing paths are silently skipped
        return files

    def _get_current_mtimes(self) -> dict[Path, float]:
        """Get modification times for all watched files."""
        mtimes: dict[Path, float] = {}
        for f in self._resolve_files():
            with contextlib.suppress(OSError):
                mtimes[f] = f.stat().st_mtime
        return mtimes

    def has_changes(self) -> bool:
        """Check if any watched files have changed since last reload.

        Returns:
            True if files have been added, removed, or modified.
        """
        current = self._get_current_mtimes()
        return current != self._mtimes

    def reload(self) -> None:
        """Reload all policy files into the Guard.

        Replaces all policies in the Guard with freshly loaded ones.
        On error (e.g. invalid YAML), the previous policies are
        retained and the error is logged.

        Deny handlers on the Guard are preserved across reloads.
        """
        files = self._resolve_files()
        new_policies: list[Policy] = []
        for f in files:
            try:
                policy = load_policy_from_yaml(f)
                new_policies.append(policy)
            except Exception:
                logger.exception("Failed to load policy from %s", f)
                # Keep existing policies on error
                self._mtimes = self._get_current_mtimes()
                return

        # Atomically replace policies
        self._guard._policies[:] = new_policies
        self._mtimes = self._get_current_mtimes()

        if self._on_reload:
            try:
                self._on_reload(new_policies)
            except Exception:
                logger.exception("on_reload callback raised an exception")

        logger.info(
            "Reloaded %d policy file(s): %s",
            len(new_policies),
            [p.name for p in new_policies],
        )

    def start(self) -> None:
        """Start the watcher background thread.

        Performs an initial reload, then polls for changes at the
        configured interval. Safe to call multiple times (no-op if
        already running).
        """
        if self.is_running:
            return
        self._stop_event.clear()
        self.reload()
        self._thread = threading.Thread(
            target=self._poll_loop,
            name="agentguard-policy-watcher",
            daemon=True,
        )
        self._thread.start()

    def stop(self) -> None:
        """Stop the watcher background thread.

        Blocks until the thread exits. Safe to call multiple times
        (no-op if not running).
        """
        if not self.is_running:
            return
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=self._poll_interval * 3)
            self._thread = None

    def _poll_loop(self) -> None:
        """Background polling loop."""
        while not self._stop_event.is_set():
            self._stop_event.wait(self._poll_interval)
            if self._stop_event.is_set():
                break
            if self.has_changes():
                self.reload()

    def __enter__(self) -> PolicyWatcher:
        """Start the watcher as a context manager."""
        self.start()
        return self

    def __exit__(self, *args: object) -> None:
        """Stop the watcher on context exit."""
        self.stop()
