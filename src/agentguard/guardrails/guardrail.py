"""Guardrail: runtime interceptor that ties policy + audit together.

The Guardrail class checks agent actions against policies before
executing them, records results in an audit log, and fires callbacks
on allow/deny events. It's the main runtime safety layer.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Callable

    from agentguard.audit.log import AuditLog
    from agentguard.guardrails.models import ActionResult, Interceptor
    from agentguard.policies.guard import Guard
    from agentguard.policies.models import Decision


@dataclass(frozen=True)
class ExecutionResult:
    """The result of a guarded action execution.

    Combines the policy decision with the optional action result.
    If the action was denied, action_result is None (it was never run).

    Attributes:
        decision: The policy engine's decision on the action.
        action_result: Result from the interceptor, or None if denied.
    """

    decision: Decision
    action_result: ActionResult | None = None


class Guardrail:
    """Runtime guardrail that composes policy checking, action execution,
    and audit logging.

    Usage::

        from agentguard.policies.guard import Guard
        from agentguard.audit.log import AuditLog
        from agentguard.guardrails.guardrail import Guardrail

        def my_executor(action_kind: str, **params: str) -> ActionResult:
            # Execute the action and return result
            ...

        guard = Guard()
        guard.load_policy_file("policies/no-force-push.yaml")

        rail = Guardrail(
            guard=guard,
            interceptor=my_executor,
            audit_log=AuditLog("session-001"),
            actor="build-agent",
            on_deny=lambda kind, dec: print(f"BLOCKED: {kind}"),
        )

        result = rail.execute("shell_command", command="git push --force")
        if result.decision.denied:
            print(f"Action blocked: {result.decision.reason}")
    """

    def __init__(
        self,
        guard: Guard,
        interceptor: Interceptor,
        audit_log: AuditLog | None = None,
        actor: str = "agent",
        on_allow: Callable[[str, Decision], None] | None = None,
        on_deny: Callable[[str, Decision], None] | None = None,
    ) -> None:
        """Initialize a Guardrail.

        Args:
            guard: The policy engine to check actions against.
            interceptor: Callable that executes allowed actions.
            audit_log: Optional audit log for recording actions.
            actor: Default actor name for audit entries.
            on_allow: Optional callback fired when an action is allowed.
            on_deny: Optional callback fired when an action is denied.
        """
        self._guard = guard
        self._interceptor = interceptor
        self._audit_log = audit_log
        self._actor = actor
        self._on_allow = on_allow
        self._on_deny = on_deny

    @property
    def guard(self) -> Guard:
        """Return the policy engine."""
        return self._guard

    @property
    def audit_log(self) -> AuditLog | None:
        """Return the audit log (if configured)."""
        return self._audit_log

    @property
    def actor(self) -> str:
        """Return the default actor name."""
        return self._actor

    def execute(self, action_kind: str, **params: str) -> ExecutionResult:
        """Execute an action through the guardrail pipeline.

        1. Check the action against all loaded policies.
        2. If denied: log, fire on_deny callback, return without executing.
        3. If allowed: execute via interceptor, log result, fire on_allow.

        Args:
            action_kind: The type of action (e.g. "shell_command").
            **params: Key-value parameters for the action.

        Returns:
            ExecutionResult with the decision and optional action result.
        """
        # Step 1: Policy check
        decision = self._guard.check(action_kind, **params)

        if decision.denied:
            # Step 2: Denied path
            self._record_audit(
                action=action_kind,
                target=self._params_to_target(params),
                result="denied",
                metadata=self._denied_metadata(decision),
            )
            if self._on_deny is not None:
                self._on_deny(action_kind, decision)
            return ExecutionResult(decision=decision, action_result=None)

        # Step 3: Allowed path — execute the action
        action_result = self._interceptor(action_kind, **params)

        # Determine audit result based on interceptor output
        audit_result = "allowed" if action_result.error is None else "error"

        self._record_audit(
            action=action_kind,
            target=self._params_to_target(params),
            result=audit_result,
        )

        if self._on_allow is not None:
            self._on_allow(action_kind, decision)

        return ExecutionResult(decision=decision, action_result=action_result)

    def _record_audit(
        self,
        action: str,
        target: str,
        result: str,
        metadata: dict[str, str] | None = None,
    ) -> None:
        """Record an audit entry if an audit log is configured."""
        if self._audit_log is not None:
            self._audit_log.record(
                action=action,
                actor=self._actor,
                target=target,
                result=result,
                metadata=metadata,
            )

    @staticmethod
    def _params_to_target(params: dict[str, str]) -> str:
        """Convert action params to a human-readable target string.

        Uses the first param value if there's exactly one,
        otherwise joins all as key=value pairs.
        """
        if not params:
            return "(no target)"
        if len(params) == 1:
            return next(iter(params.values()))
        return ", ".join(f"{k}={v}" for k, v in sorted(params.items()))

    @staticmethod
    def _denied_metadata(decision: Decision) -> dict[str, str]:
        """Build metadata dict from a denial decision."""
        meta: dict[str, str] = {}
        if decision.denied_by is not None:
            meta["denied_by"] = decision.denied_by
        if decision.reason is not None:
            meta["reason"] = decision.reason
        if decision.severity is not None:
            meta["severity"] = decision.severity.value
        return meta if meta else {}
