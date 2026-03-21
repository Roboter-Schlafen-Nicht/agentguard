"""Tests for policy versioning and changelog (M11).

Covers:
- ChangelogEntry data model
- Policy version and changelog fields
- Guard.policy_versions property
- YAML parsing of version and changelog
- Version format validation
- Changelog ordering and date parsing
- Backward compatibility
- Decision includes policy version
"""

from __future__ import annotations

import re
from datetime import date

import pytest

from agentguard.policies.guard import Guard
from agentguard.policies.loader import load_policy_from_string
from agentguard.policies.models import (
    ChangelogEntry,
    Policy,
    Rule,
    Severity,
)


def _make_policy(
    name: str = "test-policy",
    version: str | None = None,
    changelog: list[ChangelogEntry] | None = None,
) -> Policy:
    """Helper to create a Policy with a single deny rule."""
    return Policy(
        name=name,
        rules=[
            Rule(
                action_kind="shell_command",
                deny_patterns=[re.compile("rm -rf")],
                severity=Severity.CRITICAL,
            ),
        ],
        version=version,
        changelog=changelog,
    )


# --- ChangelogEntry model ---


class TestChangelogEntry:
    """Tests for the ChangelogEntry dataclass."""

    def test_create_entry(self) -> None:
        entry = ChangelogEntry(
            version="1.0.0",
            date=date(2026, 3, 21),
            description="Initial release",
        )
        assert entry.version == "1.0.0"
        assert entry.date == date(2026, 3, 21)
        assert entry.description == "Initial release"

    def test_entry_without_date(self) -> None:
        entry = ChangelogEntry(
            version="1.1.0",
            description="Added new patterns",
        )
        assert entry.date is None

    def test_entry_is_frozen(self) -> None:
        entry = ChangelogEntry(version="1.0.0", description="Initial")
        with pytest.raises(AttributeError):
            entry.version = "2.0.0"  # type: ignore[misc]


# --- Policy with version ---


class TestPolicyVersion:
    """Tests for Policy.version field."""

    def test_policy_without_version(self) -> None:
        """Backward compat: version is None by default."""
        policy = Policy(
            name="test",
            rules=[
                Rule(
                    action_kind="shell_command",
                    deny_patterns=[re.compile("rm")],
                    severity=Severity.CRITICAL,
                ),
            ],
        )
        assert policy.version is None

    def test_policy_with_version(self) -> None:
        policy = _make_policy(version="1.2.3")
        assert policy.version == "1.2.3"

    def test_policy_with_two_part_version(self) -> None:
        policy = _make_policy(version="2.1")
        assert policy.version == "2.1"

    def test_policy_with_single_version(self) -> None:
        policy = _make_policy(version="3")
        assert policy.version == "3"


# --- Policy with changelog ---


class TestPolicyChangelog:
    """Tests for Policy.changelog field."""

    def test_policy_without_changelog(self) -> None:
        policy = _make_policy()
        assert policy.changelog is None

    def test_policy_with_changelog(self) -> None:
        entries = [
            ChangelogEntry(
                version="1.1.0",
                date=date(2026, 3, 21),
                description="Added branch conditions",
            ),
            ChangelogEntry(
                version="1.0.0",
                date=date(2026, 3, 1),
                description="Initial release",
            ),
        ]
        policy = _make_policy(version="1.1.0", changelog=entries)
        assert policy.changelog is not None
        assert len(policy.changelog) == 2
        assert policy.changelog[0].version == "1.1.0"
        assert policy.changelog[1].version == "1.0.0"


# --- Guard.policy_versions ---


class TestGuardPolicyVersions:
    """Tests for Guard.policy_versions property."""

    def test_empty_guard(self) -> None:
        guard = Guard()
        assert guard.policy_versions == {}

    def test_versioned_policies(self) -> None:
        guard = Guard(
            policies=[
                _make_policy(name="p1", version="1.0.0"),
                _make_policy(name="p2", version="2.3.1"),
            ],
        )
        versions = guard.policy_versions
        assert versions == {"p1": "1.0.0", "p2": "2.3.1"}

    def test_mixed_versioned_unversioned(self) -> None:
        guard = Guard(
            policies=[
                _make_policy(name="p1", version="1.0.0"),
                _make_policy(name="p2"),  # no version
            ],
        )
        versions = guard.policy_versions
        assert versions == {"p1": "1.0.0", "p2": None}


# --- Decision includes policy version ---


class TestDecisionWithVersion:
    """Tests for Decision.policy_version field."""

    def test_denial_includes_version(self) -> None:
        guard = Guard(
            policies=[_make_policy(name="v-policy", version="2.0.0")],
        )
        decision = guard.check("shell_command", command="rm -rf /")
        assert decision.denied is True
        assert decision.policy_version == "2.0.0"

    def test_denial_without_version(self) -> None:
        guard = Guard(
            policies=[_make_policy(name="no-ver")],
        )
        decision = guard.check("shell_command", command="rm -rf /")
        assert decision.denied is True
        assert decision.policy_version is None

    def test_allowed_has_no_version(self) -> None:
        guard = Guard(
            policies=[_make_policy(name="v-policy", version="1.0.0")],
        )
        decision = guard.check("shell_command", command="echo hello")
        assert decision.allowed is True
        assert decision.policy_version is None


# --- YAML loading with version ---


class TestYAMLVersion:
    """Tests for YAML parsing of version and changelog."""

    def test_load_policy_with_version(self) -> None:
        yaml_str = """
name: versioned-policy
version: "1.2.3"
rules:
  - action: shell_command
    severity: critical
    deny:
      - pattern: 'rm -rf'
"""
        policy = load_policy_from_string(yaml_str)
        assert policy.version == "1.2.3"

    def test_load_policy_without_version(self) -> None:
        yaml_str = """
name: unversioned
rules:
  - action: shell_command
    severity: critical
    deny:
      - pattern: 'rm -rf'
"""
        policy = load_policy_from_string(yaml_str)
        assert policy.version is None

    def test_load_policy_with_changelog(self) -> None:
        yaml_str = """
name: with-changelog
version: "2.0.0"
changelog:
  - version: "2.0.0"
    date: "2026-03-21"
    description: "Added environment conditions"
  - version: "1.0.0"
    date: "2026-01-15"
    description: "Initial release"
rules:
  - action: shell_command
    severity: critical
    deny:
      - pattern: 'rm -rf'
"""
        policy = load_policy_from_string(yaml_str)
        assert policy.version == "2.0.0"
        assert policy.changelog is not None
        assert len(policy.changelog) == 2
        assert policy.changelog[0].version == "2.0.0"
        assert policy.changelog[0].date == date(2026, 3, 21)
        assert policy.changelog[0].description == "Added environment conditions"
        assert policy.changelog[1].version == "1.0.0"

    def test_changelog_without_date(self) -> None:
        yaml_str = """
name: no-date
version: "1.0.0"
changelog:
  - version: "1.0.0"
    description: "Initial release"
rules:
  - action: shell_command
    severity: critical
    deny:
      - pattern: 'rm -rf'
"""
        policy = load_policy_from_string(yaml_str)
        assert policy.changelog is not None
        assert policy.changelog[0].date is None

    def test_invalid_version_format_raises(self) -> None:
        yaml_str = """
name: bad-version
version: "not.a.valid.version.string"
rules:
  - action: shell_command
    severity: critical
    deny:
      - pattern: 'rm -rf'
"""
        with pytest.raises(ValueError, match="version"):
            load_policy_from_string(yaml_str)

    def test_invalid_changelog_date_raises(self) -> None:
        yaml_str = """
name: bad-date
version: "1.0.0"
changelog:
  - version: "1.0.0"
    date: "not-a-date"
    description: "Bad"
rules:
  - action: shell_command
    severity: critical
    deny:
      - pattern: 'rm -rf'
"""
        with pytest.raises(ValueError, match="date"):
            load_policy_from_string(yaml_str)

    def test_changelog_entry_missing_version_raises(self) -> None:
        yaml_str = """
name: missing-ver
version: "1.0.0"
changelog:
  - description: "No version"
rules:
  - action: shell_command
    severity: critical
    deny:
      - pattern: 'rm -rf'
"""
        with pytest.raises(ValueError, match="version"):
            load_policy_from_string(yaml_str)

    def test_changelog_entry_missing_description_raises(self) -> None:
        yaml_str = """
name: missing-desc
version: "1.0.0"
changelog:
  - version: "1.0.0"
rules:
  - action: shell_command
    severity: critical
    deny:
      - pattern: 'rm -rf'
"""
        with pytest.raises(ValueError, match="description"):
            load_policy_from_string(yaml_str)


# --- End-to-end ---


class TestVersioningEndToEnd:
    """End-to-end tests: YAML → Guard → versioned check."""

    def test_versioned_policy_round_trip(self) -> None:
        yaml_str = """
name: production-safety
version: "3.1.0"
description: Production environment safety rules
changelog:
  - version: "3.1.0"
    date: "2026-03-21"
    description: "Added data deletion protection"
  - version: "3.0.0"
    date: "2026-02-01"
    description: "Major overhaul of deny patterns"
rules:
  - action: shell_command
    severity: critical
    deny:
      - pattern: 'rm -rf'
"""
        guard = Guard()
        guard.load_policy_string(yaml_str)

        assert guard.policy_versions == {"production-safety": "3.1.0"}

        decision = guard.check("shell_command", command="rm -rf /")
        assert decision.denied is True
        assert decision.policy_version == "3.1.0"
        assert decision.denied_by == "production-safety"
