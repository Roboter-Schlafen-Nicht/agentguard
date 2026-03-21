"""Built-in deny action handlers for policy violations.

Provides handlers that can be registered with :meth:`Guard.on_deny` to
receive notifications when a policy denies an action. All handlers use
only Python standard library modules (zero external dependencies).

Usage::

    from agentguard.policies.guard import Guard
    from agentguard.policies.handlers import WebhookHandler

    guard = Guard(policies=[...])
    guard.on_deny(WebhookHandler(url="https://example.com/webhook"))

Handlers follow the ``DenyHandler`` protocol: any callable accepting
``(Decision, Action)`` can be used. The built-in classes implement
``__call__`` for this purpose.
"""

from __future__ import annotations

import json
import logging
from email.mime.text import MIMEText
from smtplib import SMTP
from typing import TYPE_CHECKING
from urllib.request import Request, urlopen

if TYPE_CHECKING:
    from agentguard.policies.models import Action, Decision

logger = logging.getLogger(__name__)


class WebhookHandler:
    """Send a JSON POST request to a webhook URL on policy deny.

    The payload includes event type, policy name, severity, action
    kind, reason, action parameters, and policy version.

    Args:
        url: The webhook URL to POST to.
        headers: Optional additional HTTP headers.
        timeout: Request timeout in seconds (default 10).

    Raises:
        ValueError: If url is empty.
    """

    def __init__(
        self,
        url: str,
        headers: dict[str, str] | None = None,
        timeout: int = 10,
    ) -> None:
        if not url:
            msg = "url must not be empty"
            raise ValueError(msg)
        self.url = url
        self.headers = headers or {}
        self.timeout = timeout

    def __call__(self, decision: Decision, action: Action) -> None:
        """Send webhook notification."""
        payload = {
            "event": "policy_deny",
            "policy": decision.denied_by,
            "severity": decision.severity.value if decision.severity else None,
            "reason": decision.reason,
            "action_kind": action.kind,
            "action_params": dict(action.params),
            "policy_version": decision.policy_version,
        }
        data = json.dumps(payload).encode("utf-8")
        request = Request(
            self.url,
            data=data,
            method="POST",
        )
        request.add_header("Content-Type", "application/json")
        for key, value in self.headers.items():
            request.add_header(key, value)

        with urlopen(request, timeout=self.timeout):
            pass


class SlackHandler:
    """Send a formatted message to a Slack webhook on policy deny.

    Uses Slack's incoming webhook format with a text field containing
    the deny details.

    Args:
        webhook_url: The Slack incoming webhook URL.
        channel: Optional channel override (e.g., "#security").
        timeout: Request timeout in seconds (default 10).

    Raises:
        ValueError: If webhook_url is empty.
    """

    def __init__(
        self,
        webhook_url: str,
        channel: str | None = None,
        timeout: int = 10,
    ) -> None:
        if not webhook_url:
            msg = "webhook_url must not be empty"
            raise ValueError(msg)
        self.webhook_url = webhook_url
        self.channel = channel
        self.timeout = timeout

    def __call__(self, decision: Decision, action: Action) -> None:
        """Send Slack notification."""
        severity = decision.severity.value.upper() if decision.severity else "UNKNOWN"
        text = (
            f":rotating_light: *Policy Deny* [{severity}]\n"
            f"*Policy:* {decision.denied_by}"
        )
        if decision.policy_version:
            text += f" (v{decision.policy_version})"
        text += f"\n*Action:* {action.kind}\n*Reason:* {decision.reason}"

        payload: dict[str, str] = {"text": text}
        if self.channel:
            payload["channel"] = self.channel

        data = json.dumps(payload).encode("utf-8")
        request = Request(
            self.webhook_url,
            data=data,
            method="POST",
        )
        request.add_header("Content-Type", "application/json")

        with urlopen(request, timeout=self.timeout):
            pass


class EmailHandler:
    """Send an email notification on policy deny via SMTP.

    Uses Python's built-in ``smtplib`` module. Supports optional
    TLS and authentication.

    Args:
        smtp_host: SMTP server hostname.
        smtp_port: SMTP server port (typically 587 for TLS, 25 for
            plain).
        from_addr: Sender email address.
        to_addrs: List of recipient email addresses.
        username: Optional SMTP username for authentication.
        password: Optional SMTP password for authentication.
        use_tls: Whether to use STARTTLS (default False).
        timeout: SMTP connection timeout in seconds (default 30).

    Raises:
        ValueError: If smtp_host is empty or to_addrs is empty.
    """

    def __init__(
        self,
        smtp_host: str,
        smtp_port: int,
        from_addr: str,
        to_addrs: list[str],
        username: str | None = None,
        password: str | None = None,
        use_tls: bool = False,
        timeout: int = 30,
    ) -> None:
        if not smtp_host:
            msg = "smtp_host must not be empty"
            raise ValueError(msg)
        if not to_addrs:
            msg = "to_addrs must not be empty"
            raise ValueError(msg)
        self.smtp_host = smtp_host
        self.smtp_port = smtp_port
        self.from_addr = from_addr
        self.to_addrs = to_addrs
        self.username = username
        self.password = password
        self.use_tls = use_tls
        self.timeout = timeout

    def __call__(self, decision: Decision, action: Action) -> None:
        """Send email notification."""
        severity = decision.severity.value.upper() if decision.severity else "UNKNOWN"
        subject = f"[AgentGuard] Policy Deny [{severity}]: {decision.denied_by}"
        body = (
            f"Policy: {decision.denied_by}\n"
            f"Severity: {severity}\n"
            f"Action: {action.kind}\n"
            f"Reason: {decision.reason}\n"
            f"Parameters: {dict(action.params)}\n"
        )
        if decision.policy_version:
            body += f"Policy version: {decision.policy_version}\n"

        msg = MIMEText(body, "plain", "utf-8")
        msg["Subject"] = subject
        msg["From"] = self.from_addr
        msg["To"] = ", ".join(self.to_addrs)

        with SMTP(self.smtp_host, self.smtp_port, timeout=self.timeout) as smtp:
            if self.use_tls:
                smtp.starttls()
            if self.username and self.password:
                smtp.login(self.username, self.password)
            smtp.sendmail(self.from_addr, self.to_addrs, msg.as_string())
