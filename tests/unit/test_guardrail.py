"""Tests for M3 Runtime Guardrails — Guardrail class."""

from __future__ import annotations

from typing import TYPE_CHECKING

from agentguard.audit.log import AuditLog
from agentguard.guardrails.guardrail import Guardrail
from agentguard.guardrails.models import ActionResult
from agentguard.policies.builtins import load_all_builtins
from agentguard.policies.guard import Guard

if TYPE_CHECKING:
    from agentguard.policies.models import Decision


def _echo_interceptor(action_kind: str, **params: str) -> ActionResult:
    """Simple interceptor that echoes back the action."""
    return ActionResult(
        action_kind=action_kind,
        params=params,
        executed=True,
        output=f"executed {action_kind}",
    )


def _failing_interceptor(action_kind: str, **params: str) -> ActionResult:
    """Interceptor that simulates an error."""
    return ActionResult(
        action_kind=action_kind,
        params=params,
        executed=True,
        output=None,
        error="something went wrong",
    )


class TestGuardrailInit:
    """Tests for Guardrail initialization."""

    def test_create_with_guard_and_interceptor(self) -> None:
        """Guardrail is initialized with a Guard and interceptor."""
        guard = Guard()
        rail = Guardrail(guard=guard, interceptor=_echo_interceptor)
        assert rail.guard is guard

    def test_create_with_audit_log(self) -> None:
        """Guardrail can be given an AuditLog for recording."""
        guard = Guard()
        log = AuditLog("test-session")
        rail = Guardrail(
            guard=guard,
            interceptor=_echo_interceptor,
            audit_log=log,
        )
        assert rail.audit_log is log

    def test_create_without_audit_log(self) -> None:
        """Guardrail works without an AuditLog."""
        guard = Guard()
        rail = Guardrail(guard=guard, interceptor=_echo_interceptor)
        assert rail.audit_log is None

    def test_create_with_actor(self) -> None:
        """Guardrail can be given a default actor name."""
        guard = Guard()
        rail = Guardrail(
            guard=guard,
            interceptor=_echo_interceptor,
            actor="my-agent",
        )
        assert rail.actor == "my-agent"

    def test_default_actor_is_agent(self) -> None:
        """Default actor name is 'agent'."""
        guard = Guard()
        rail = Guardrail(guard=guard, interceptor=_echo_interceptor)
        assert rail.actor == "agent"


class TestGuardrailExecute:
    """Tests for Guardrail.execute() — the main API."""

    def test_allowed_action_is_executed(self) -> None:
        """When policy allows an action, the interceptor runs."""
        guard = Guard()  # No policies = allow all
        rail = Guardrail(guard=guard, interceptor=_echo_interceptor)
        result = rail.execute("shell_command", command="echo hello")
        assert result.decision.allowed is True
        assert result.action_result is not None
        assert result.action_result.executed is True
        assert result.action_result.output == "executed shell_command"

    def test_denied_action_is_not_executed(self) -> None:
        """When policy denies an action, the interceptor does NOT run."""
        guard = Guard()
        for policy in load_all_builtins():
            guard.add_policy(policy)
        rail = Guardrail(guard=guard, interceptor=_echo_interceptor)
        result = rail.execute(
            "shell_command",
            command="git push --force origin main",
        )
        assert result.decision.denied is True
        assert result.action_result is None

    def test_denied_action_has_decision_details(self) -> None:
        """Denied result carries the policy name and severity."""
        guard = Guard()
        for policy in load_all_builtins():
            guard.add_policy(policy)
        rail = Guardrail(guard=guard, interceptor=_echo_interceptor)
        result = rail.execute(
            "shell_command",
            command="git push --force origin main",
        )
        assert result.decision.denied_by is not None
        assert result.decision.severity is not None

    def test_execute_with_error_interceptor(self) -> None:
        """When interceptor returns an error, it's captured."""
        guard = Guard()
        rail = Guardrail(guard=guard, interceptor=_failing_interceptor)
        result = rail.execute("shell_command", command="bad-cmd")
        assert result.decision.allowed is True
        assert result.action_result is not None
        assert result.action_result.error == "something went wrong"


class TestGuardrailAuditIntegration:
    """Tests for Guardrail + AuditLog integration."""

    def test_allowed_action_is_recorded_in_audit_log(self) -> None:
        """Allowed actions are recorded with result='allowed'."""
        guard = Guard()
        log = AuditLog("test-session")
        rail = Guardrail(
            guard=guard,
            interceptor=_echo_interceptor,
            audit_log=log,
        )
        rail.execute("shell_command", command="echo hello")
        assert len(log.entries) == 1
        entry = log.entries[0]
        assert entry.action == "shell_command"
        assert entry.result == "allowed"
        assert entry.actor == "agent"

    def test_denied_action_is_recorded_in_audit_log(self) -> None:
        """Denied actions are recorded with result='denied'."""
        guard = Guard()
        for policy in load_all_builtins():
            guard.add_policy(policy)
        log = AuditLog("test-session")
        rail = Guardrail(
            guard=guard,
            interceptor=_echo_interceptor,
            audit_log=log,
        )
        rail.execute("shell_command", command="git push --force origin main")
        assert len(log.entries) == 1
        entry = log.entries[0]
        assert entry.result == "denied"
        assert entry.actor == "agent"

    def test_audit_entry_has_target_from_params(self) -> None:
        """Audit entry target is derived from action params."""
        guard = Guard()
        log = AuditLog("test-session")
        rail = Guardrail(
            guard=guard,
            interceptor=_echo_interceptor,
            audit_log=log,
        )
        rail.execute("shell_command", command="echo hello")
        entry = log.entries[0]
        # Target should be a string representation of params
        assert "echo hello" in entry.target

    def test_audit_entry_uses_custom_actor(self) -> None:
        """Audit entry uses the Guardrail's actor name."""
        guard = Guard()
        log = AuditLog("test-session")
        rail = Guardrail(
            guard=guard,
            interceptor=_echo_interceptor,
            audit_log=log,
            actor="build-agent",
        )
        rail.execute("shell_command", command="echo hello")
        entry = log.entries[0]
        assert entry.actor == "build-agent"

    def test_multiple_executions_chain_audit_entries(self) -> None:
        """Multiple executions produce a valid hash chain."""
        guard = Guard()
        log = AuditLog("test-session")
        rail = Guardrail(
            guard=guard,
            interceptor=_echo_interceptor,
            audit_log=log,
        )
        rail.execute("shell_command", command="echo 1")
        rail.execute("shell_command", command="echo 2")
        rail.execute("file_write", path="/tmp/test.txt")
        assert len(log.entries) == 3
        assert log.verify()

    def test_error_action_recorded_with_error_result(self) -> None:
        """Interceptor errors are recorded with result='error'."""
        guard = Guard()
        log = AuditLog("test-session")
        rail = Guardrail(
            guard=guard,
            interceptor=_failing_interceptor,
            audit_log=log,
        )
        rail.execute("shell_command", command="bad-cmd")
        entry = log.entries[0]
        assert entry.result == "error"

    def test_denied_audit_has_policy_metadata(self) -> None:
        """Denied audit entry metadata includes policy name."""
        guard = Guard()
        for policy in load_all_builtins():
            guard.add_policy(policy)
        log = AuditLog("test-session")
        rail = Guardrail(
            guard=guard,
            interceptor=_echo_interceptor,
            audit_log=log,
        )
        rail.execute("shell_command", command="git push --force origin main")
        entry = log.entries[0]
        assert entry.metadata is not None
        assert "denied_by" in entry.metadata

    def test_no_audit_log_does_not_crash(self) -> None:
        """Execute works fine without an audit log."""
        guard = Guard()
        rail = Guardrail(guard=guard, interceptor=_echo_interceptor)
        result = rail.execute("shell_command", command="echo hello")
        assert result.decision.allowed is True


class TestGuardrailCallbacks:
    """Tests for on_allow and on_deny callbacks."""

    def test_on_allow_callback_called(self) -> None:
        """on_allow callback is called when action is allowed."""
        called_with: list[str] = []

        def on_allow(action_kind: str, decision: Decision) -> None:
            called_with.append(action_kind)

        guard = Guard()
        rail = Guardrail(
            guard=guard,
            interceptor=_echo_interceptor,
            on_allow=on_allow,
        )
        rail.execute("shell_command", command="echo hello")
        assert called_with == ["shell_command"]

    def test_on_deny_callback_called(self) -> None:
        """on_deny callback is called when action is denied."""
        called_with: list[tuple[str, str | None]] = []

        def on_deny(action_kind: str, decision: Decision) -> None:
            called_with.append((action_kind, decision.denied_by))

        guard = Guard()
        for policy in load_all_builtins():
            guard.add_policy(policy)
        rail = Guardrail(
            guard=guard,
            interceptor=_echo_interceptor,
            on_deny=on_deny,
        )
        rail.execute("shell_command", command="git push --force origin main")
        assert len(called_with) == 1
        assert called_with[0][0] == "shell_command"
        assert called_with[0][1] is not None

    def test_on_allow_not_called_when_denied(self) -> None:
        """on_allow is NOT called when action is denied."""
        allow_called: list[str] = []

        def on_allow(action_kind: str, decision: Decision) -> None:
            allow_called.append(action_kind)

        guard = Guard()
        for policy in load_all_builtins():
            guard.add_policy(policy)
        rail = Guardrail(
            guard=guard,
            interceptor=_echo_interceptor,
            on_allow=on_allow,
        )
        rail.execute("shell_command", command="git push --force origin main")
        assert allow_called == []

    def test_on_deny_not_called_when_allowed(self) -> None:
        """on_deny is NOT called when action is allowed."""
        deny_called: list[str] = []

        def on_deny(action_kind: str, decision: Decision) -> None:
            deny_called.append(action_kind)

        guard = Guard()
        rail = Guardrail(
            guard=guard,
            interceptor=_echo_interceptor,
            on_deny=on_deny,
        )
        rail.execute("shell_command", command="echo hello")
        assert deny_called == []

    def test_callbacks_are_optional(self) -> None:
        """Guardrail works fine without callbacks."""
        guard = Guard()
        rail = Guardrail(guard=guard, interceptor=_echo_interceptor)
        result = rail.execute("shell_command", command="echo hello")
        assert result.decision.allowed is True
