"""Policy auto-discovery.

Automatically discovers and loads policy YAML files from standard
locations, enabling private/custom policies without explicit CLI flags.

Discovery order (first found wins for duplicate policy names):
1. ``$AGENTGUARD_POLICY_DIR`` — colon-separated list of directories
2. Project-level: ``.agentguard/policies/`` relative to CWD
3. User-level: ``~/.agentguard/policies/``

All directories are scanned for ``*.yaml`` files. Files are loaded
alphabetically within each directory. If two directories contain a
policy with the same name, the one from the higher-priority directory
is kept.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import TYPE_CHECKING

from agentguard.policies.loader import load_policy_from_yaml

if TYPE_CHECKING:
    from agentguard.policies.models import Policy

logger = logging.getLogger(__name__)

_ENV_VAR = "AGENTGUARD_POLICY_DIR"


def default_project_dir() -> Path:
    """Return the default project-level policy directory.

    Returns:
        ``.agentguard/policies/`` relative to the current working directory.
    """
    return Path.cwd() / ".agentguard" / "policies"


def default_user_dir() -> Path:
    """Return the default user-level policy directory.

    Returns:
        ``~/.agentguard/policies/``.
    """
    return Path.home() / ".agentguard" / "policies"


def discover_policy_dirs(
    *,
    project_dir: Path | None = None,
    user_dir: Path | None = None,
) -> list[Path]:
    """Discover directories containing policy YAML files.

    Checks (in priority order):
    1. Directories from ``$AGENTGUARD_POLICY_DIR`` (colon-separated)
    2. Project-level directory
    3. User-level directory

    Only directories that actually exist are returned. Duplicates
    (by resolved path) are removed.

    Args:
        project_dir: Project-level policy directory to check.
        user_dir: User-level policy directory to check.

    Returns:
        List of existing directories, ordered by priority.
    """
    candidates: list[Path] = []

    # 1. Environment variable directories
    env_value = os.environ.get(_ENV_VAR, "").strip()
    if env_value:
        for part in env_value.split(":"):
            part = part.strip()
            if part:
                candidates.append(Path(part))

    # 2. Project-level
    if project_dir is not None:
        candidates.append(project_dir)

    # 3. User-level
    if user_dir is not None:
        candidates.append(user_dir)

    # Filter to existing directories and deduplicate by resolved path
    seen: set[Path] = set()
    result: list[Path] = []
    for candidate in candidates:
        resolved = candidate.resolve()
        if resolved not in seen and candidate.is_dir():
            seen.add(resolved)
            result.append(candidate)

    return result


def discover_policies(
    *,
    project_dir: Path | None = None,
    user_dir: Path | None = None,
) -> list[Policy]:
    """Discover and load policies from standard locations.

    Scans directories returned by :func:`discover_policy_dirs` for
    ``*.yaml`` files and loads them as policies. Files are loaded
    alphabetically within each directory. If two directories contain
    a policy with the same ``name``, the one from the higher-priority
    directory is kept (first wins).

    Invalid YAML files are skipped with a warning log.

    Args:
        project_dir: Project-level policy directory to check.
        user_dir: User-level policy directory to check.

    Returns:
        List of loaded Policy objects, deduplicated by name.
    """
    dirs = discover_policy_dirs(project_dir=project_dir, user_dir=user_dir)

    seen_names: set[str] = set()
    policies: list[Policy] = []

    for policy_dir in dirs:
        for yaml_file in sorted(policy_dir.glob("*.yaml")):
            try:
                policy = load_policy_from_yaml(yaml_file)
            except Exception:
                logger.warning("Skipping invalid policy file: %s", yaml_file)
                continue

            if policy.name not in seen_names:
                seen_names.add(policy.name)
                policies.append(policy)

    return policies


def auto_discover() -> list[Policy]:
    """Discover policies using default project and user directories.

    Convenience wrapper around :func:`discover_policies` that uses
    :func:`default_project_dir` and :func:`default_user_dir`.

    Returns:
        List of auto-discovered Policy objects.
    """
    return discover_policies(
        project_dir=default_project_dir(),
        user_dir=default_user_dir(),
    )
