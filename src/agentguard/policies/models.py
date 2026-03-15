"""Policy data models: Severity, Action, Rule, Decision, Policy.

These are the core types used throughout the AgentGuard policy engine.
All are immutable (frozen dataclasses or enums) for safety.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import re


class Severity(enum.Enum):
    """Risk severity level for a policy rule.

    Severities are ordered: LOW < MEDIUM < HIGH < CRITICAL.
    """

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        order = list(Severity)
        return order.index(self) < order.index(other)

    def __le__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self == other or self.__lt__(other)

    def __gt__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        order = list(Severity)
        return order.index(self) > order.index(other)

    def __ge__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self == other or self.__gt__(other)


class ScanTarget(enum.Enum):
    """Target field to scan when evaluating deny patterns.

    Specifies which parameter to apply deny patterns against.
    Used by LLM proxy rules and MCP tool rules to target specific
    parameters instead of scanning all values.

    Values:
        MESSAGES: Scan the concatenated message content.
        SYSTEM: Scan only the system prompt.
        CONTENT: Scan the response content or file content.
        ALL: Scan all parameter values (same as default behavior).
        COMMAND: Scan only the command parameter (shell_execute).
        NEW_STRING: Scan only the new_string parameter (file_edit).
    """

    MESSAGES = "messages"
    SYSTEM = "system"
    CONTENT = "content"
    ALL = "all"
    COMMAND = "command"
    NEW_STRING = "new_string"


@dataclass(frozen=True)
class Action:
    """An action an agent wants to perform.

    Attributes:
        kind: The type of action (e.g., "shell_command", "file_write").
        params: Key-value parameters for the action.
    """

    kind: str
    params: dict[str, str] = field(default_factory=dict)


@dataclass
class Rule:
    """A deny rule within a policy.

    A rule matches an action if:
    1. The action's kind matches the rule's action_kind
    2. Any of the rule's deny_patterns match any string value in the
       action's params

    When ``scan`` is set, patterns are matched only against the
    specified parameter key instead of all values. This is used by
    LLM proxy policies to target specific parts of the request or
    response (e.g., scan only message content, not metadata).

    Attributes:
        action_kind: The kind of action this rule applies to.
        deny_patterns: Compiled regex patterns. If any matches any
            param value, the action is denied.
        severity: How severe a violation of this rule is.
        description: Optional human-readable description.
        scan: Optional scan target for LLM proxy rules. When None
            (default), all param values are scanned. When set,
            only the specified param key is scanned.
    """

    action_kind: str
    deny_patterns: list[re.Pattern[str]]
    severity: Severity
    description: str | None = None
    scan: ScanTarget | None = None

    def matches(self, action: Action) -> bool:
        """Check if this rule matches the given action."""
        if action.kind != self.action_kind:
            return False
        if self.scan is not None:
            return self._matches_scan_target(action)
        for pattern in self.deny_patterns:
            for value in action.params.values():
                if isinstance(value, str) and pattern.search(value):
                    return True
        return False

    def _matches_scan_target(self, action: Action) -> bool:
        """Match patterns against a specific param key or all values."""
        if self.scan is None:  # pragma: no cover — caller guarantees scan is set
            return False
        if self.scan == ScanTarget.ALL:
            for pattern in self.deny_patterns:
                for value in action.params.values():
                    if isinstance(value, str) and pattern.search(value):
                        return True
            return False
        # Scan only the specified key
        key = self.scan.value
        target_value = action.params.get(key)
        if not isinstance(target_value, str):
            return False
        return any(pattern.search(target_value) for pattern in self.deny_patterns)


@dataclass(frozen=True)
class Decision:
    """The result of evaluating an action against a policy.

    Attributes:
        allowed: Whether the action is allowed.
        denied_by: Name of the policy that denied it (if denied).
        reason: Human-readable explanation (if denied).
        severity: Severity of the violated rule (if denied).
    """

    allowed: bool
    denied_by: str | None = None
    reason: str | None = None
    severity: Severity | None = None

    @property
    def denied(self) -> bool:
        """Convenience: True if the action was denied."""
        return not self.allowed


@dataclass
class Policy:
    """A named collection of rules that govern agent behavior.

    Attributes:
        name: Unique identifier for this policy.
        description: Human-readable description.
        rules: List of deny rules. First match wins.
    """

    name: str
    rules: list[Rule]
    description: str | None = None

    def evaluate(self, action: Action) -> Decision:
        """Evaluate an action against all rules in this policy.

        Returns the first matching rule's decision, or allows if none match.
        """
        for rule in self.rules:
            if rule.matches(action):
                return Decision(
                    allowed=False,
                    denied_by=self.name,
                    reason=f"Blocked by policy: {self.name}",
                    severity=rule.severity,
                )
        return Decision(allowed=True)
