"""Policy data models for the AgentGuard policy engine.

Core types: Severity, Action, Rule, Decision, Policy, Condition,
Context, ChangelogEntry. All are immutable (frozen dataclasses or
enums) for safety.
"""

from __future__ import annotations

import enum
import fnmatch
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import re
    from datetime import date, datetime, time


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


@dataclass(frozen=True)
class Context:
    """Runtime context for conditional policy evaluation.

    Provides environmental information used by :class:`Condition` to
    determine whether a rule is active. All fields are optional; when
    a condition references a context field that is ``None``, the
    condition is considered *not met* (fail-closed for the condition,
    meaning the rule is skipped).

    Attributes:
        time: Current UTC timestamp. Used by time-of-day and weekday
            conditions.
        environment: Deployment environment name (e.g., "production",
            "staging", "development").
        branch: Current git branch name. Supports fnmatch-style
            patterns in conditions (e.g., ``"feature/*"``).
        variables: Additional custom key-value context for future
            extensibility.
    """

    time: datetime | None = None
    environment: str | None = None
    branch: str | None = None
    variables: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class Condition:
    """Conditions that must be met for a rule to be active.

    All specified conditions are AND-combined: every non-None field
    must match the provided :class:`Context` for the condition to be
    met. If a condition field is ``None``, it imposes no constraint.

    YAML example::

        conditions:
          time_after: "09:00"
          time_before: "17:00"
          environment: production
          branch: main
          weekdays: [0, 1, 2, 3, 4]

    Attributes:
        time_after: Rule is active only after this time of day (UTC).
        time_before: Rule is active only before this time of day (UTC).
        environment: Rule is active only in this environment
            (case-insensitive match).
        branch: Rule is active only on this branch. Supports
            fnmatch-style patterns (e.g., ``"feature/*"``).
        weekdays: Rule is active only on these days of the week.
            Monday=0 through Sunday=6 (ISO weekday numbering).
    """

    time_after: time | None = None
    time_before: time | None = None
    environment: str | None = None
    branch: str | None = None
    weekdays: list[int] | None = None

    def is_met(self, ctx: Context) -> bool:
        """Evaluate whether all conditions are satisfied by the context.

        Args:
            ctx: The runtime context to check against.

        Returns:
            True if all specified conditions are met.
        """
        if self.time_after is not None:
            if ctx.time is None:
                return False
            if ctx.time.time() < self.time_after:
                return False

        if self.time_before is not None:
            if ctx.time is None:
                return False
            if ctx.time.time() >= self.time_before:
                return False

        if self.weekdays is not None:
            if ctx.time is None:
                return False
            if ctx.time.weekday() not in self.weekdays:
                return False

        if self.environment is not None:
            if ctx.environment is None:
                return False
            if self.environment.lower() != ctx.environment.lower():
                return False

        if self.branch is not None:
            if ctx.branch is None:
                return False
            if not fnmatch.fnmatch(ctx.branch, self.branch):
                return False

        return True


@dataclass(frozen=True)
class ChangelogEntry:
    """A single entry in a policy's changelog.

    Attributes:
        version: The version this entry describes.
        description: Human-readable description of what changed.
        date: Optional date of the change (ISO 8601 format in YAML).
    """

    version: str
    description: str
    date: date | None = None


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
        min_unique_chars: Optional minimum unique character count for
            regex matches. When set, a regex match is only treated as
            a denial if the matched text contains at least this many
            distinct characters. This filters out low-entropy
            placeholders (e.g., all-A fake API keys) while still
            catching real secrets with high character diversity.
    """

    action_kind: str
    deny_patterns: list[re.Pattern[str]]
    severity: Severity
    description: str | None = None
    scan: ScanTarget | None = None
    min_unique_chars: int | None = None
    conditions: Condition | None = None

    def _has_sufficient_entropy(self, match: re.Match[str]) -> bool:
        """Check if a regex match has enough unique characters.

        When ``min_unique_chars`` is set, the matched text must contain
        at least that many distinct characters.  This filters out
        low-entropy placeholder strings like ``sk-proj-AAAAAAAAAA``
        (only 8 unique chars) while still catching real secrets with
        high entropy (20+ unique chars).

        Returns True if the match has sufficient entropy (should deny),
        or if ``min_unique_chars`` is not set (backward compat).
        """
        if self.min_unique_chars is None:
            return True
        matched_text = match.group()
        unique_count = len(set(matched_text))
        return unique_count >= self.min_unique_chars

    def matches(self, action: Action, context: Context | None = None) -> bool:
        """Check if this rule matches the given action.

        When the rule has conditions, they are checked against the
        provided context first. If conditions are not met (or context
        is missing when conditions require it), the rule is skipped.

        Args:
            action: The action to check.
            context: Optional runtime context for conditional evaluation.

        Returns:
            True if the rule matches (action should be denied).
        """
        if action.kind != self.action_kind:
            return False
        if self.conditions is not None:
            if context is None:
                return False
            if not self.conditions.is_met(context):
                return False
        if self.scan is not None:
            return self._matches_scan_target(action)
        for pattern in self.deny_patterns:
            for value in action.params.values():
                if isinstance(value, str):
                    for match in pattern.finditer(value):
                        if self._has_sufficient_entropy(match):
                            return True
        return False

    def _matches_scan_target(self, action: Action) -> bool:
        """Match patterns against a specific param key or all values."""
        if self.scan is None:  # pragma: no cover — caller guarantees scan is set
            return False
        if self.scan == ScanTarget.ALL:
            for pattern in self.deny_patterns:
                for value in action.params.values():
                    if isinstance(value, str):
                        for match in pattern.finditer(value):
                            if self._has_sufficient_entropy(match):
                                return True
            return False
        # Scan only the specified key
        key = self.scan.value
        target_value = action.params.get(key)
        if not isinstance(target_value, str):
            return False
        for pattern in self.deny_patterns:
            for match in pattern.finditer(target_value):
                if self._has_sufficient_entropy(match):
                    return True
        return False


@dataclass(frozen=True)
class Decision:
    """The result of evaluating an action against a policy.

    Attributes:
        allowed: Whether the action is allowed.
        denied_by: Name of the policy that denied it (if denied).
        reason: Human-readable explanation (if denied).
        severity: Severity of the violated rule (if denied).
        policy_version: Version of the denying policy (if denied and
            the policy has a version).
    """

    allowed: bool
    denied_by: str | None = None
    reason: str | None = None
    severity: Severity | None = None
    policy_version: str | None = None

    @property
    def denied(self) -> bool:
        """Convenience: True if the action was denied."""
        return not self.allowed


@dataclass
class Policy:
    """A named collection of rules that govern agent behavior.

    Attributes:
        name: Unique identifier for this policy.
        rules: List of deny rules. First match wins.
        description: Human-readable description.
        version: Optional semver-like version string.
        changelog: Optional list of changelog entries (newest first).
    """

    name: str
    rules: list[Rule]
    description: str | None = None
    version: str | None = None
    changelog: list[ChangelogEntry] | None = None

    def evaluate(self, action: Action, context: Context | None = None) -> Decision:
        """Evaluate an action against all rules in this policy.

        Args:
            action: The action to check.
            context: Optional runtime context for conditional rules.

        Returns:
            The first matching rule's decision, or allows if none match.
        """
        for rule in self.rules:
            if rule.matches(action, context=context):
                return Decision(
                    allowed=False,
                    denied_by=self.name,
                    reason=f"Blocked by policy: {self.name}",
                    severity=rule.severity,
                    policy_version=self.version,
                )
        return Decision(allowed=True)
