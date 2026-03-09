"""SG-6: Guardrail → Guard → AuditLog Full Chain.

Integration tests for the Guardrail class with real Guard policies
and real AuditLog (no mocking of core components).
"""

from __future__ import annotations

import pytest

from agentguard.audit.log import AuditLog
from agentguard.guardrails.guardrail import ExecutionResult, Guardrail
from agentguard.guardrails.models import ActionResult
from agentguard.policies.guard import Guard

pytestmark = pytest.mark.integration


# ---------------------------------------------------------------------------
# Helper interceptor
# ---------------------------------------------------------------------------


class RecordingInterceptor:
    """Interceptor that records calls and returns success."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, str]]] = []

    def __call__(self, action_kind: str, **params: str) -> ActionResult:
        self.calls.append((action_kind, params))
        return ActionResult(
            action_kind=action_kind,
            params=params,
            executed=True,
            output="ok",
        )


# ===========================================================================
# SG-6.1: Guardrail.execute() denied action recorded in audit
# ===========================================================================


class TestGuardrailDenied:
    """SG-6.1: Denied action recorded in audit, interceptor not called."""

    def test_denied_action_audit_and_no_interceptor(self) -> None:
        """Denied action creates audit entry; interceptor is never invoked."""
        guard = Guard()
        guard.load_policy_string(
            "name: deny-rm\n"
            "rules:\n"
            "  - action: shell_command\n"
            "    deny:\n"
            "      - pattern: 'rm -rf'\n"
            "    severity: critical\n"
        )

        audit_log = AuditLog("session-guardrail-1")
        interceptor = RecordingInterceptor()

        rail = Guardrail(
            guard=guard,
            interceptor=interceptor,
            audit_log=audit_log,
            actor="test-agent",
        )

        result = rail.execute("shell_command", command="rm -rf /")

        assert isinstance(result, ExecutionResult)
        assert result.decision.denied
        assert result.action_result is None

        # Interceptor was NOT called
        assert len(interceptor.calls) == 0

        # Audit has 1 entry with result=denied
        entries = audit_log.entries
        assert len(entries) == 1
        assert entries[0].action == "shell_command"
        assert entries[0].result == "denied"
        assert entries[0].metadata is not None
        assert entries[0].metadata.get("denied_by") == "deny-rm"


# ===========================================================================
# SG-6.2: Guardrail.execute() allowed action invokes interceptor
# ===========================================================================


class TestGuardrailAllowed:
    """SG-6.2: Allowed action invokes interceptor and records in audit."""

    def test_allowed_action_calls_interceptor(self) -> None:
        """Allowed action runs interceptor and creates audit entry."""
        guard = Guard()  # No policies = everything allowed

        audit_log = AuditLog("session-guardrail-2")
        interceptor = RecordingInterceptor()

        rail = Guardrail(
            guard=guard,
            interceptor=interceptor,
            audit_log=audit_log,
            actor="test-agent",
        )

        result = rail.execute("shell_command", command="echo hello")

        assert not result.decision.denied
        assert result.action_result is not None
        assert result.action_result.executed
        assert result.action_result.output == "ok"

        # Interceptor was called with correct args
        assert len(interceptor.calls) == 1
        assert interceptor.calls[0] == ("shell_command", {"command": "echo hello"})

        # Audit has 1 entry with result=allowed
        entries = audit_log.entries
        assert len(entries) == 1
        assert entries[0].result == "allowed"


# ===========================================================================
# SG-6.3: Guardrail with builtins end-to-end
# ===========================================================================


class TestGuardrailWithBuiltins:
    """SG-6.3: Guardrail with all builtins denies dangerous content."""

    def test_builtins_deny_secret_in_file_write(self) -> None:
        """file_write with AWS secret key is denied by builtins."""
        guard = Guard.with_auto_discovery(include_builtins=True)
        audit_log = AuditLog("session-guardrail-3")
        interceptor = RecordingInterceptor()

        rail = Guardrail(
            guard=guard,
            interceptor=interceptor,
            audit_log=audit_log,
            actor="test-agent",
        )

        result = rail.execute(
            "file_write",
            content="aws_secret_access_key=" + "AKIA" + "IOSFODNN7EXAMPLE",
        )

        assert result.decision.denied
        assert result.decision.denied_by == "no-secret-exposure"

        # Interceptor was NOT called
        assert len(interceptor.calls) == 0

        # Audit records the denial
        entries = audit_log.entries
        assert len(entries) == 1
        assert entries[0].result == "denied"
