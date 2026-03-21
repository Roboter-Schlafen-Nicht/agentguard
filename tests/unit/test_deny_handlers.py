"""Tests for custom deny action handlers (M11).

Covers:
- Guard.on_deny() registration
- Handler invocation on deny
- Handler not invoked on allow
- Multiple handlers
- Handler errors are caught (don't affect deny decision)
- WebhookHandler: sends POST with JSON payload
- SlackHandler: sends Slack-formatted message
- EmailHandler: sends SMTP email
- Built-in handler configuration and validation
"""

from __future__ import annotations

import json
import re
from unittest.mock import MagicMock, patch

import pytest

from agentguard.policies.guard import Guard
from agentguard.policies.handlers import EmailHandler, SlackHandler, WebhookHandler
from agentguard.policies.models import (
    Action,
    Decision,
    Policy,
    Rule,
    Severity,
)


def _deny_policy(name: str = "test") -> Policy:
    """Helper: a policy that denies 'rm -rf'."""
    return Policy(
        name=name,
        version="1.0.0",
        rules=[
            Rule(
                action_kind="shell_command",
                deny_patterns=[re.compile("rm -rf")],
                severity=Severity.CRITICAL,
            ),
        ],
    )


# --- Guard.on_deny registration and invocation ---


class TestGuardOnDeny:
    """Tests for Guard.on_deny() and handler invocation."""

    def test_register_handler(self) -> None:
        guard = Guard()
        handler = MagicMock()
        result = guard.on_deny(handler)
        assert result is guard  # method chaining

    def test_handler_called_on_deny(self) -> None:
        handler = MagicMock()
        guard = Guard(policies=[_deny_policy()])
        guard.on_deny(handler)

        decision = guard.check("shell_command", command="rm -rf /")

        assert decision.denied is True
        handler.assert_called_once()
        call_args = handler.call_args
        assert isinstance(call_args[0][0], Decision)
        assert isinstance(call_args[0][1], Action)
        assert call_args[0][0].denied is True

    def test_handler_not_called_on_allow(self) -> None:
        handler = MagicMock()
        guard = Guard(policies=[_deny_policy()])
        guard.on_deny(handler)

        decision = guard.check("shell_command", command="echo hello")

        assert decision.allowed is True
        handler.assert_not_called()

    def test_multiple_handlers_all_called(self) -> None:
        handler1 = MagicMock()
        handler2 = MagicMock()
        guard = Guard(policies=[_deny_policy()])
        guard.on_deny(handler1)
        guard.on_deny(handler2)

        guard.check("shell_command", command="rm -rf /")

        handler1.assert_called_once()
        handler2.assert_called_once()

    def test_handler_error_does_not_affect_decision(self) -> None:
        """Handler exceptions are caught; deny decision is still returned."""
        bad_handler = MagicMock(side_effect=RuntimeError("boom"))
        good_handler = MagicMock()
        guard = Guard(policies=[_deny_policy()])
        guard.on_deny(bad_handler)
        guard.on_deny(good_handler)

        decision = guard.check("shell_command", command="rm -rf /")

        assert decision.denied is True
        bad_handler.assert_called_once()
        good_handler.assert_called_once()  # Still called despite first error

    def test_handler_receives_correct_action(self) -> None:
        handler = MagicMock()
        guard = Guard(policies=[_deny_policy()])
        guard.on_deny(handler)

        guard.check("shell_command", command="rm -rf /home")

        _, action = handler.call_args[0]
        assert action.kind == "shell_command"
        assert action.params["command"] == "rm -rf /home"

    def test_handler_receives_policy_version(self) -> None:
        handler = MagicMock()
        guard = Guard(policies=[_deny_policy()])
        guard.on_deny(handler)

        guard.check("shell_command", command="rm -rf /")

        decision, _ = handler.call_args[0]
        assert decision.policy_version == "1.0.0"


# --- WebhookHandler ---


class TestWebhookHandler:
    """Tests for WebhookHandler."""

    def test_create_webhook_handler(self) -> None:
        handler = WebhookHandler(url="https://example.com/webhook")
        assert handler.url == "https://example.com/webhook"

    def test_webhook_sends_post_request(self) -> None:
        handler = WebhookHandler(url="https://example.com/hook")
        decision = Decision(
            allowed=False,
            denied_by="test-policy",
            reason="Blocked by policy: test-policy",
            severity=Severity.CRITICAL,
            policy_version="1.0.0",
        )
        action = Action(kind="shell_command", params={"command": "rm -rf /"})

        with patch("agentguard.policies.handlers.urlopen") as mock_urlopen:
            mock_urlopen.return_value.__enter__ = MagicMock()
            mock_urlopen.return_value.__exit__ = MagicMock(
                return_value=False,
            )
            handler(decision, action)

        mock_urlopen.assert_called_once()
        request = mock_urlopen.call_args[0][0]
        assert request.full_url == "https://example.com/hook"
        assert request.method == "POST"
        assert request.get_header("Content-type") == "application/json"

        body = json.loads(request.data.decode())
        assert body["event"] == "policy_deny"
        assert body["policy"] == "test-policy"
        assert body["severity"] == "critical"
        assert body["action_kind"] == "shell_command"
        assert body["policy_version"] == "1.0.0"

    def test_webhook_custom_headers(self) -> None:
        handler = WebhookHandler(
            url="https://example.com/hook",
            headers={"Authorization": "Bearer token123"},
        )
        decision = Decision(
            allowed=False,
            denied_by="p",
            reason="r",
            severity=Severity.HIGH,
        )
        action = Action(kind="test", params={})

        with patch("agentguard.policies.handlers.urlopen") as mock_urlopen:
            mock_urlopen.return_value.__enter__ = MagicMock()
            mock_urlopen.return_value.__exit__ = MagicMock(
                return_value=False,
            )
            handler(decision, action)

        request = mock_urlopen.call_args[0][0]
        assert request.get_header("Authorization") == "Bearer token123"

    def test_webhook_url_required(self) -> None:
        with pytest.raises(ValueError, match="url"):
            WebhookHandler(url="")


# --- SlackHandler ---


class TestSlackHandler:
    """Tests for SlackHandler."""

    def test_create_slack_handler(self) -> None:
        handler = SlackHandler(webhook_url="https://hooks.slack.com/xxx")
        assert handler.webhook_url == "https://hooks.slack.com/xxx"

    def test_slack_sends_formatted_message(self) -> None:
        handler = SlackHandler(webhook_url="https://hooks.slack.com/xxx")
        decision = Decision(
            allowed=False,
            denied_by="safety-policy",
            reason="Blocked by policy: safety-policy",
            severity=Severity.CRITICAL,
            policy_version="2.0.0",
        )
        action = Action(
            kind="shell_command",
            params={"command": "rm -rf /"},
        )

        with patch("agentguard.policies.handlers.urlopen") as mock_urlopen:
            mock_urlopen.return_value.__enter__ = MagicMock()
            mock_urlopen.return_value.__exit__ = MagicMock(
                return_value=False,
            )
            handler(decision, action)

        mock_urlopen.assert_called_once()
        request = mock_urlopen.call_args[0][0]
        body = json.loads(request.data.decode())
        assert "text" in body
        assert "safety-policy" in body["text"]
        assert "CRITICAL" in body["text"]

    def test_slack_custom_channel(self) -> None:
        handler = SlackHandler(
            webhook_url="https://hooks.slack.com/xxx",
            channel="#security",
        )
        decision = Decision(
            allowed=False,
            denied_by="p",
            reason="r",
            severity=Severity.HIGH,
        )
        action = Action(kind="test", params={})

        with patch("agentguard.policies.handlers.urlopen") as mock_urlopen:
            mock_urlopen.return_value.__enter__ = MagicMock()
            mock_urlopen.return_value.__exit__ = MagicMock(
                return_value=False,
            )
            handler(decision, action)

        request = mock_urlopen.call_args[0][0]
        body = json.loads(request.data.decode())
        assert body["channel"] == "#security"

    def test_slack_url_required(self) -> None:
        with pytest.raises(ValueError, match="webhook_url"):
            SlackHandler(webhook_url="")


# --- EmailHandler ---


class TestEmailHandler:
    """Tests for EmailHandler."""

    def test_create_email_handler(self) -> None:
        handler = EmailHandler(
            smtp_host="smtp.example.com",
            smtp_port=587,
            from_addr="alerts@example.com",
            to_addrs=["admin@example.com"],
        )
        assert handler.smtp_host == "smtp.example.com"
        assert handler.to_addrs == ["admin@example.com"]

    def test_email_sends_message(self) -> None:
        handler = EmailHandler(
            smtp_host="smtp.example.com",
            smtp_port=587,
            from_addr="alerts@example.com",
            to_addrs=["admin@example.com"],
        )
        decision = Decision(
            allowed=False,
            denied_by="prod-policy",
            reason="Blocked by policy: prod-policy",
            severity=Severity.CRITICAL,
            policy_version="1.0.0",
        )
        action = Action(
            kind="shell_command",
            params={"command": "rm -rf /"},
        )

        with patch("agentguard.policies.handlers.SMTP") as mock_smtp_cls:
            mock_smtp = MagicMock()
            mock_smtp_cls.return_value.__enter__ = MagicMock(
                return_value=mock_smtp,
            )
            mock_smtp_cls.return_value.__exit__ = MagicMock(
                return_value=False,
            )
            handler(decision, action)

        mock_smtp_cls.assert_called_once_with(
            "smtp.example.com",
            587,
            timeout=30,
        )
        mock_smtp.sendmail.assert_called_once()
        call_args = mock_smtp.sendmail.call_args
        assert call_args[0][0] == "alerts@example.com"
        assert call_args[0][1] == ["admin@example.com"]
        body: str = call_args[0][2]
        assert "prod-policy" in body
        assert "CRITICAL" in body

    def test_email_with_auth(self) -> None:
        handler = EmailHandler(
            smtp_host="smtp.example.com",
            smtp_port=587,
            from_addr="alerts@example.com",
            to_addrs=["admin@example.com"],
            username="user",
            password="pass",
            use_tls=True,
        )

        decision = Decision(
            allowed=False,
            denied_by="p",
            reason="r",
            severity=Severity.LOW,
        )
        action = Action(kind="test", params={})

        with patch("agentguard.policies.handlers.SMTP") as mock_smtp_cls:
            mock_smtp = MagicMock()
            mock_smtp_cls.return_value.__enter__ = MagicMock(
                return_value=mock_smtp,
            )
            mock_smtp_cls.return_value.__exit__ = MagicMock(
                return_value=False,
            )
            handler(decision, action)

        mock_smtp.starttls.assert_called_once()
        mock_smtp.login.assert_called_once_with("user", "pass")

    def test_email_host_required(self) -> None:
        with pytest.raises(ValueError, match="smtp_host"):
            EmailHandler(
                smtp_host="",
                smtp_port=587,
                from_addr="a@b.com",
                to_addrs=["c@d.com"],
            )

    def test_email_to_addrs_required(self) -> None:
        with pytest.raises(ValueError, match="to_addrs"):
            EmailHandler(
                smtp_host="smtp.example.com",
                smtp_port=587,
                from_addr="a@b.com",
                to_addrs=[],
            )


# --- Integration: Guard + handlers end-to-end ---


class TestGuardHandlerIntegration:
    """End-to-end tests: Guard with registered handlers."""

    def test_guard_with_webhook_handler(self) -> None:
        guard = Guard(policies=[_deny_policy()])
        with patch("agentguard.policies.handlers.urlopen") as mock_urlopen:
            mock_urlopen.return_value.__enter__ = MagicMock()
            mock_urlopen.return_value.__exit__ = MagicMock(
                return_value=False,
            )
            guard.on_deny(WebhookHandler(url="https://example.com/hook"))
            decision = guard.check("shell_command", command="rm -rf /")

        assert decision.denied is True
        mock_urlopen.assert_called_once()

    def test_guard_mixed_handlers(self) -> None:
        """Multiple handler types registered together."""
        guard = Guard(policies=[_deny_policy()])
        mock_handler = MagicMock()
        guard.on_deny(mock_handler)

        with patch("agentguard.policies.handlers.urlopen") as mock_urlopen:
            mock_urlopen.return_value.__enter__ = MagicMock()
            mock_urlopen.return_value.__exit__ = MagicMock(
                return_value=False,
            )
            guard.on_deny(WebhookHandler(url="https://example.com/hook"))
            decision = guard.check("shell_command", command="rm -rf /")

        assert decision.denied is True
        mock_handler.assert_called_once()
        mock_urlopen.assert_called_once()
