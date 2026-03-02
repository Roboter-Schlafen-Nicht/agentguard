"""Tests for M3 Runtime Guardrails — interceptor protocol and models."""

from __future__ import annotations

from agentguard.guardrails.models import ActionResult, Interceptor


class TestInterceptor:
    """Tests for the Interceptor protocol."""

    def test_interceptor_is_callable_protocol(self) -> None:
        """Interceptor is a Protocol that accepts action_kind and params."""

        def my_interceptor(action_kind: str, **params: str) -> ActionResult:
            return ActionResult(
                action_kind=action_kind,
                params=params,
                executed=True,
                output="done",
            )

        # The interceptor should satisfy the protocol
        interceptor: Interceptor = my_interceptor
        result = interceptor("shell_command", command="echo hello")
        assert result.executed is True
        assert result.output == "done"

    def test_interceptor_can_be_a_class(self) -> None:
        """Interceptor can be implemented as a class with __call__."""

        class MyInterceptor:
            def __call__(self, action_kind: str, **params: str) -> ActionResult:
                return ActionResult(
                    action_kind=action_kind,
                    params=params,
                    executed=True,
                    output=f"ran {action_kind}",
                )

        interceptor: Interceptor = MyInterceptor()
        result = interceptor("file_write", path="/tmp/test.txt")
        assert result.executed is True
        assert result.output == "ran file_write"


class TestActionResult:
    """Tests for the ActionResult model."""

    def test_create_successful_result(self) -> None:
        """ActionResult can represent a successful execution."""
        result = ActionResult(
            action_kind="shell_command",
            params={"command": "echo hello"},
            executed=True,
            output="hello",
        )
        assert result.action_kind == "shell_command"
        assert result.params == {"command": "echo hello"}
        assert result.executed is True
        assert result.output == "hello"
        assert result.error is None

    def test_create_failed_result(self) -> None:
        """ActionResult can represent a failed execution."""
        result = ActionResult(
            action_kind="shell_command",
            params={"command": "bad-cmd"},
            executed=True,
            output=None,
            error="command not found",
        )
        assert result.executed is True
        assert result.output is None
        assert result.error == "command not found"

    def test_create_blocked_result(self) -> None:
        """ActionResult can represent a blocked (not executed) action."""
        result = ActionResult(
            action_kind="shell_command",
            params={"command": "rm -rf /"},
            executed=False,
        )
        assert result.executed is False
        assert result.output is None
        assert result.error is None

    def test_default_output_and_error_are_none(self) -> None:
        """Output and error default to None."""
        result = ActionResult(
            action_kind="test",
            params={},
            executed=True,
        )
        assert result.output is None
        assert result.error is None
