"""Runtime guardrail models: ActionResult and Interceptor protocol.

These types define the contract for agent action execution and the
interceptor pattern used by the Guardrail class.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol


@dataclass(frozen=True)
class ActionResult:
    """The result of executing an agent action via an interceptor.

    Attributes:
        action_kind: The type of action that was executed.
        params: The parameters passed to the action.
        executed: Whether the action was actually executed.
        output: Output from the action (if any).
        error: Error message (if the action failed).
    """

    action_kind: str
    params: dict[str, str] = field(default_factory=dict)
    executed: bool = False
    output: str | None = None
    error: str | None = None


class Interceptor(Protocol):
    """Protocol for agent action interceptors.

    An interceptor is any callable that takes an action_kind and
    keyword parameters, executes the action, and returns an
    ActionResult. The Guardrail class calls the interceptor only
    when the policy engine allows the action.

    Implementations can be functions or classes with __call__.
    """

    def __call__(self, action_kind: str, **params: str) -> ActionResult:
        """Execute an agent action.

        Args:
            action_kind: The type of action to execute.
            **params: Key-value parameters for the action.

        Returns:
            An ActionResult describing the outcome.
        """
        ...
