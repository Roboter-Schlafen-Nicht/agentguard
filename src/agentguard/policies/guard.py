"""Guard: the central policy enforcement point.

The Guard class loads and manages policies, and evaluates agent actions
against all loaded policies. It's the main public API for AgentGuard's
policy engine.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from agentguard.policies.loader import load_policy_from_string, load_policy_from_yaml
from agentguard.policies.models import Action, Decision, Policy

if TYPE_CHECKING:
    from pathlib import Path


class Guard:
    """Central policy enforcement point.

    A Guard manages a collection of policies and checks agent actions
    against all of them. The first policy that denies an action wins.

    Usage::

        guard = Guard()
        guard.add_policy(my_policy)
        result = guard.check("shell_command", command="rm -rf /")
        if result.denied:
            print(result.reason)
    """

    def __init__(self, policies: list[Policy] | None = None) -> None:
        """Initialize a Guard.

        Args:
            policies: Optional list of policies to start with.
        """
        self._policies: list[Policy] = list(policies) if policies else []

    @classmethod
    def with_auto_discovery(cls, *, include_builtins: bool = False) -> Guard:
        """Create a Guard with auto-discovered policies.

        Loads policies from standard locations:
        1. ``$AGENTGUARD_POLICY_DIR`` (colon-separated directories)
        2. ``.agentguard/policies/`` (project-level, relative to CWD)
        3. ``~/.agentguard/policies/`` (user-level)

        Args:
            include_builtins: Also load AgentGuard's built-in policies
                (appended after discovered policies).

        Returns:
            A new Guard instance with discovered (and optionally
            built-in) policies loaded.
        """
        from agentguard.policies.builtins import load_all_builtins
        from agentguard.policies.discovery import auto_discover

        policies = auto_discover()

        if include_builtins:
            seen_names = {p.name for p in policies}
            for builtin in load_all_builtins():
                if builtin.name not in seen_names:
                    seen_names.add(builtin.name)
                    policies.append(builtin)

        return cls(policies=policies)

    @property
    def policies(self) -> list[Policy]:
        """Return the list of loaded policies."""
        return self._policies

    def add_policy(self, policy: Policy) -> Guard:
        """Add a policy to the guard.

        Args:
            policy: The policy to add.

        Returns:
            Self, for method chaining.
        """
        self._policies.append(policy)
        return self

    def load_policy_string(self, yaml_str: str) -> Guard:
        """Load a policy from a YAML string and add it.

        Args:
            yaml_str: YAML-formatted policy definition.

        Returns:
            Self, for method chaining.
        """
        policy = load_policy_from_string(yaml_str)
        self._policies.append(policy)
        return self

    def load_policy_file(self, path: str | Path) -> Guard:
        """Load a policy from a YAML file and add it.

        Args:
            path: Path to the YAML policy file.

        Returns:
            Self, for method chaining.
        """
        policy = load_policy_from_yaml(path)
        self._policies.append(policy)
        return self

    def check(self, action_kind: str, **params: str) -> Decision:
        """Check an action against all loaded policies.

        Args:
            action_kind: The type of action (e.g. "shell_command").
            **params: Key-value parameters for the action.

        Returns:
            A Decision indicating whether the action is allowed or denied.
        """
        action = Action(kind=action_kind, params=params)
        for policy in self._policies:
            decision = policy.evaluate(action)
            if decision.denied:
                return decision
        return Decision(allowed=True)
