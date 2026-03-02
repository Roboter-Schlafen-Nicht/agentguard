"""Built-in policy loader.

Provides access to AgentGuard's bundled policy definitions:
- no-force-push: Prevent destructive git operations
- no-secret-exposure: Prevent writing secrets/credentials
- no-data-deletion: Prevent destructive data operations
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from agentguard.policies.loader import load_policy_from_yaml

if TYPE_CHECKING:
    from agentguard.policies.models import Policy

_BUILTIN_DIR = Path(__file__).parent / "builtin_policies"


def list_builtins() -> list[str]:
    """List the names of all available built-in policies.

    Returns:
        Sorted list of built-in policy names.
    """
    return sorted(p.stem for p in _BUILTIN_DIR.glob("*.yaml"))


def load_builtin(name: str) -> Policy:
    """Load a built-in policy by name.

    Args:
        name: The name of the built-in policy (e.g. "no-force-push").

    Returns:
        The loaded Policy object.

    Raises:
        ValueError: If no built-in policy with that name exists.
    """
    path = _BUILTIN_DIR / f"{name}.yaml"
    if not path.exists():
        available = ", ".join(list_builtins())
        msg = f"No built-in policy named '{name}'. Available: {available}"
        raise ValueError(msg)
    return load_policy_from_yaml(path)


def load_all_builtins() -> list[Policy]:
    """Load all built-in policies.

    Returns:
        List of all built-in Policy objects.
    """
    return [load_builtin(name) for name in list_builtins()]
