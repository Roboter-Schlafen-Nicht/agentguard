"""YAML policy loader and validator.

Parses YAML policy definitions into Policy objects. Validates structure,
required fields, regex patterns, and severity values.

Zero external dependencies — uses Python's built-in yaml support via
the standard library. (PyYAML is a dependency, but it's ubiquitous.)
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

from agentguard.policies.models import Policy, Rule, Severity


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

    return Rule(
        action_kind=data["action"],
        deny_patterns=patterns,
        severity=severity,
        description=data.get("description"),
    )


def _parse_severity(value: str) -> Severity:
    """Parse a severity string into a Severity enum."""
    try:
        return Severity(value)
    except ValueError:
        valid = ", ".join(s.value for s in Severity)
        msg = f"Invalid severity '{value}'. Valid values: {valid}"
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
