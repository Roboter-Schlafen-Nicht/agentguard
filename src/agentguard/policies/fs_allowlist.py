"""Filesystem allowlist policy type.

Provides a policy that allows file operations only when the target
path is within an allowlist. Supports exact paths, directory prefixes
(trailing ``/``), and glob patterns. Built-in presets for common safe
locations.

Usage::

    from agentguard.policies.fs_allowlist import FilesystemAllowlist
    from agentguard.policies.guard import Guard

    policy = FilesystemAllowlist(
        name="file-access",
        allowed_paths=["/home/user/project/", "/tmp/"],
        presets=["temp"],
        action_kind="file_write",
    )
    guard = Guard(policies=[policy])
    decision = guard.check("file_write", path="/home/user/project/out.txt")

YAML format::

    name: file-access
    type: fs_allowlist
    action: file_write
    paths:
      - /home/user/project/
      - /tmp/
      - "*.py"
    presets:
      - temp
"""

from __future__ import annotations

import logging
from fnmatch import fnmatch
from pathlib import PurePosixPath

from agentguard.policies.models import Action, Context, Decision, Policy, Severity

logger = logging.getLogger(__name__)

#: Built-in filesystem presets.
FS_PRESETS: dict[str, list[str]] = {
    "temp": [
        "/tmp/",
        "/var/tmp/",
    ],
    "project": [
        "./",
    ],
    "home": [
        "/home/",
    ],
    "logs": [
        "/var/log/",
        "/tmp/logs/",
    ],
}


class FilesystemAllowlist(Policy):
    """Policy that allows file operations only for whitelisted paths.

    Checks ``path`` and ``file`` parameters in actions against an
    allowlist. Supports:

    - **Exact paths**: ``/home/user/config.yaml`` matches only
      that file.
    - **Directory prefixes**: ``/home/user/project/`` (trailing
      slash) matches all files under that directory.
    - **Glob patterns**: ``/home/user/project/*.py`` matches via
      fnmatch.

    All paths are normalized (resolving ``..`` and ``.``) before
    matching to prevent path traversal.

    Args:
        name: Policy name.
        allowed_paths: List of allowed path patterns.
        presets: List of preset names to include.
        action_kind: The action kind this policy applies to
            (default: ``file_write``).
        description: Optional description.

    Raises:
        ValueError: If neither allowed_paths nor presets are provided,
            or if an unknown preset is referenced.
    """

    def __init__(
        self,
        name: str,
        allowed_paths: list[str] | None = None,
        presets: list[str] | None = None,
        action_kind: str = "file_write",
        description: str | None = None,
    ) -> None:
        if not allowed_paths and not presets:
            msg = "At least one of allowed_paths or presets must be provided"
            raise ValueError(msg)

        # Validate presets
        if presets:
            for preset in presets:
                if preset not in FS_PRESETS:
                    msg = f"Unknown preset: {preset!r}"
                    raise ValueError(msg)

        # Build the full path set
        all_paths: list[str] = []
        if allowed_paths:
            all_paths.extend(allowed_paths)
        if presets:
            for preset in presets:
                all_paths.extend(FS_PRESETS[preset])

        # Categorize paths
        self._exact_paths: set[str] = set()
        self._dir_prefixes: list[str] = []
        self._glob_patterns: list[str] = []

        for p in all_paths:
            if p.endswith("/"):
                # Directory prefix
                self._dir_prefixes.append(p)
            elif any(c in p for c in ("*", "?", "[", "]")):
                # Glob pattern
                self._glob_patterns.append(p)
            else:
                # Exact path
                self._exact_paths.add(p)

        self._action_kind = action_kind

        super().__init__(
            name=name,
            rules=[],
            description=description,
        )

    def evaluate(
        self,
        action: Action,
        context: Context | None = None,
    ) -> Decision:
        """Evaluate an action against the filesystem allowlist.

        Checks ``path`` and ``file`` params. If the action kind
        doesn't match, the action is allowed (pass-through).

        Args:
            action: The action to check.
            context: Unused (present for API compatibility).

        Returns:
            Allow if path is in allowlist, deny otherwise.
        """
        if action.kind != self._action_kind:
            return Decision(allowed=True)

        # Try to extract path from params
        target = self._extract_path(action)
        if target is None:
            return Decision(
                allowed=False,
                denied_by=self.name,
                reason=(f"No path found in action params (policy: {self.name})"),
                severity=Severity.HIGH,
            )

        return self.evaluate_path(target)

    def evaluate_path(self, path: str) -> Decision:
        """Check a path string against the allowlist.

        The path is normalized before checking to prevent traversal
        attacks.

        Args:
            path: The filesystem path to check.

        Returns:
            Allow if path is in allowlist, deny otherwise.
        """
        # Normalize the path to resolve .. and .
        normalized = str(PurePosixPath(path).as_posix())
        # Use pathlib to resolve '..' components
        # PurePosixPath doesn't resolve .., so we do it manually
        normalized = _normalize_path(path)

        # Exact match
        if normalized in self._exact_paths:
            return Decision(allowed=True)

        # Directory prefix match
        for prefix in self._dir_prefixes:
            if normalized.startswith(prefix) or normalized + "/" == prefix:
                return Decision(allowed=True)

        # Glob pattern match
        for pattern in self._glob_patterns:
            if fnmatch(normalized, pattern):
                return Decision(allowed=True)

        return Decision(
            allowed=False,
            denied_by=self.name,
            reason=(f"Path {path!r} not in allowlist (policy: {self.name})"),
            severity=Severity.HIGH,
        )

    def _extract_path(self, action: Action) -> str | None:
        """Extract path from action params.

        Checks ``path`` param first, then ``file``.
        """
        path = action.params.get("path")
        if isinstance(path, str) and path:
            return path

        file_param = action.params.get("file")
        if isinstance(file_param, str) and file_param:
            return file_param

        return None


def _normalize_path(path: str) -> str:
    """Normalize a filesystem path, resolving '..' and '.' components.

    Uses PurePosixPath for consistent cross-platform normalization
    without filesystem access.

    Args:
        path: The path to normalize.

    Returns:
        Normalized absolute-style path.
    """
    parts: list[str] = []
    is_absolute = path.startswith("/")

    for part in PurePosixPath(path).parts:
        if part == "/":
            continue
        if part == ".":
            continue
        if part == "..":
            if parts:
                parts.pop()
        else:
            parts.append(part)

    result = "/".join(parts)
    if is_absolute:
        result = "/" + result
    return result
