"""YAML policy loader and validator.

Parses YAML policy definitions into Policy objects. Validates structure,
required fields, regex patterns, and severity values.

Zero external dependencies — uses Python's built-in yaml support via
the standard library. (PyYAML is a dependency, but it's ubiquitous.)
"""

from __future__ import annotations

import re
from datetime import time
from pathlib import Path
from typing import Any

import yaml

from agentguard.policies.models import Condition, Policy, Rule, ScanTarget, Severity


def load_policy_from_string(yaml_str: str) -> Policy:
    """Parse a YAML string into a Policy object.

    Args:
        yaml_str: YAML-formatted policy definition.

    Returns:
        A validated Policy object.

    Raises:
        ValueError: If the YAML is missing required fields or has
            invalid values.
    """
    data = yaml.safe_load(yaml_str)
    if not isinstance(data, dict):
        msg = "Policy YAML must be a mapping"
        raise ValueError(msg)
    return _parse_policy(data)


def load_policy_from_yaml(path: str | Path) -> Policy:
    """Load a policy from a YAML file.

    Args:
        path: Path to the YAML file (str or Path).

    Returns:
        A validated Policy object.

    Raises:
        FileNotFoundError: If the file does not exist.
        ValueError: If the YAML is missing required fields or has
            invalid values.
    """
    file_path = Path(path)
    if not file_path.exists():
        msg = f"Policy file not found: {file_path}"
        raise FileNotFoundError(msg)
    text = file_path.read_text(encoding="utf-8")
    return load_policy_from_string(text)


def _parse_policy(data: dict[str, Any]) -> Policy:
    """Parse and validate a policy dict."""
    if "name" not in data:
        msg = "Policy must have a 'name' field"
        raise ValueError(msg)

    if "rules" not in data or not data["rules"]:
        msg = "Policy must have a non-empty 'rules' field"
        raise ValueError(msg)

    rules = [_parse_rule(r) for r in data["rules"]]
    return Policy(
        name=data["name"],
        description=data.get("description"),
        rules=rules,
    )


def _parse_rule(data: Any) -> Rule:
    """Parse and validate a single rule dict."""
    if not isinstance(data, dict):
        msg = "Each rule must be a mapping"
        raise ValueError(msg)

    if "action" not in data:
        msg = "Each rule must have an 'action' field"
        raise ValueError(msg)

    if "deny" not in data or not data["deny"]:
        msg = "Each rule must have a non-empty 'deny' field"
        raise ValueError(msg)

    if "severity" not in data:
        msg = "Each rule must have a 'severity' field"
        raise ValueError(msg)

    severity = _parse_severity(data["severity"])
    patterns = [_parse_pattern(p) for p in data["deny"]]
    scan = _parse_scan_target(data["scan"]) if "scan" in data else None
    min_unique_chars = _parse_min_unique_chars(data.get("min_unique_chars"))
    conditions = _parse_conditions(data["conditions"]) if "conditions" in data else None

    return Rule(
        action_kind=data["action"],
        deny_patterns=patterns,
        severity=severity,
        description=data.get("description"),
        scan=scan,
        min_unique_chars=min_unique_chars,
        conditions=conditions,
    )


def _parse_severity(value: str) -> Severity:
    """Parse a severity string into a Severity enum."""
    try:
        return Severity(value)
    except ValueError:
        valid = ", ".join(s.value for s in Severity)
        msg = f"Invalid severity '{value}'. Valid values: {valid}"
        raise ValueError(msg) from None


def _parse_scan_target(value: str) -> ScanTarget:
    """Parse a scan target string into a ScanTarget enum.

    Args:
        value: Scan target string (e.g., "messages", "system", "content", "all").

    Returns:
        The corresponding ScanTarget enum value.

    Raises:
        ValueError: If the value is not a valid scan target.
    """
    try:
        return ScanTarget(value)
    except ValueError:
        valid = ", ".join(s.value for s in ScanTarget)
        msg = f"Invalid scan target '{value}'. Valid values: {valid}"
        raise ValueError(msg) from None


def _parse_pattern(data: Any) -> re.Pattern[str]:
    """Parse a deny pattern entry into a compiled regex."""
    if not isinstance(data, dict):
        msg = "Each deny entry must be a mapping with a 'pattern' key"
        raise ValueError(msg)

    if "pattern" not in data:
        msg = "Each deny entry must have a 'pattern' key"
        raise ValueError(msg)

    try:
        return re.compile(data["pattern"])
    except re.error as e:
        msg = f"Invalid regex pattern '{data['pattern']}': {e}"
        raise ValueError(msg) from e


def _parse_min_unique_chars(value: Any) -> int | None:
    """Parse and validate the optional min_unique_chars field.

    Args:
        value: Raw value from YAML (None if absent).

    Returns:
        Validated positive integer, or None if not set.

    Raises:
        ValueError: If the value is not a positive integer.
    """
    if value is None:
        return None
    if not isinstance(value, int) or isinstance(value, bool):
        msg = f"min_unique_chars must be a positive integer, got: {value!r}"
        raise ValueError(msg)
    if value < 1:
        msg = f"min_unique_chars must be a positive integer (>= 1), got: {value}"
        raise ValueError(msg)
    return value


_VALID_CONDITION_FIELDS = frozenset(
    {
        "time_after",
        "time_before",
        "environment",
        "branch",
        "weekdays",
    }
)


def _parse_conditions(data: Any) -> Condition:
    """Parse and validate a conditions block into a Condition.

    Args:
        data: Raw conditions dict from YAML.

    Returns:
        A validated Condition object.

    Raises:
        ValueError: If the conditions block has invalid fields or values.
    """
    if not isinstance(data, dict):
        msg = "conditions must be a mapping"
        raise ValueError(msg)

    unknown = set(data.keys()) - _VALID_CONDITION_FIELDS
    if unknown:
        msg = f"Unknown condition field(s): {', '.join(sorted(unknown))}"
        raise ValueError(msg)

    time_after = _parse_time_field(data.get("time_after"), "time_after")
    time_before = _parse_time_field(data.get("time_before"), "time_before")
    environment: str | None = data.get("environment")
    if environment is not None:
        environment = str(environment)
    branch: str | None = data.get("branch")
    if branch is not None:
        branch = str(branch)
    weekdays = _parse_weekdays(data.get("weekdays"))

    return Condition(
        time_after=time_after,
        time_before=time_before,
        environment=environment,
        branch=branch,
        weekdays=weekdays,
    )


def _parse_time_field(value: Any, field_name: str) -> time | None:
    """Parse a time string (HH:MM) into a time object.

    Args:
        value: Raw value from YAML (None if absent, str if present).
        field_name: Field name for error messages.

    Returns:
        A time object, or None if value is None.

    Raises:
        ValueError: If the value is not a valid HH:MM time string.
    """
    if value is None:
        return None
    value_str = str(value)
    try:
        parts = value_str.split(":")
        if len(parts) != 2:
            raise ValueError
        hour, minute = int(parts[0]), int(parts[1])
        return time(hour, minute)
    except (ValueError, IndexError):
        msg = f"Invalid {field_name} value '{value_str}'. Expected HH:MM format"
        raise ValueError(msg) from None


def _parse_weekdays(value: Any) -> list[int] | None:
    """Parse and validate a weekdays list.

    Args:
        value: Raw value from YAML (None if absent, list if present).

    Returns:
        A validated list of integers (0-6), or None if value is None.

    Raises:
        ValueError: If any weekday value is not in 0-6 range.
    """
    if value is None:
        return None
    if not isinstance(value, list):
        msg = f"weekdays must be a list of integers (0-6), got: {type(value).__name__}"
        raise ValueError(msg)
    for day in value:
        if not isinstance(day, int) or isinstance(day, bool) or day < 0 or day > 6:
            msg = f"Invalid weekday value {day!r}. Must be 0 (Mon) through 6 (Sun)"
            raise ValueError(msg)
    return value
