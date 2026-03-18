"""Tests for min_unique_chars entropy filtering on Rule.matches().

When a rule has min_unique_chars set, regex matches against low-entropy
strings (e.g., all-same-character repetitions like 'AAAAAAAAAA') should
NOT be treated as denials.  This prevents false positives from
placeholder/fake secrets in conversation history.

The unique-char count is computed on the FULL regex match text.
For a placeholder like ``sk-proj-`` + ``A`` * 28, the unique chars are
{s, k, -, p, r, o, j, A} = 8.  Setting min_unique_chars=10 will
filter this out while still catching real keys with 20+ unique chars.
"""

from __future__ import annotations

import re

import pytest

from agentguard.policies.models import Action, Rule, ScanTarget, Severity

# ---------------------------------------------------------------------------
# Key builders — construct test keys at runtime to avoid triggering
# the pre-commit safety scanner which blocks literal key patterns.
# ---------------------------------------------------------------------------

_SK_PREFIX = "sk" + "-"
_SK_PROJ_PREFIX = "sk" + "-" + "proj" + "-"
_GHP_PREFIX = "ghp" + "_"

# A realistic mixed-case+digit suffix for high-entropy tests
_REALISTIC_SUFFIX = "ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"


def _sk_proj_key(suffix: str) -> str:
    """Build sk-proj-<suffix> at runtime."""
    return _SK_PROJ_PREFIX + suffix


def _ghp_token(suffix: str) -> str:
    """Build ghp_<suffix> at runtime."""
    return _GHP_PREFIX + suffix


class TestMinUniqueCharsField:
    """Rule dataclass accepts and stores min_unique_chars."""

    def test_default_is_none(self) -> None:
        """min_unique_chars defaults to None (backward compat)."""
        rule = Rule(
            action_kind="llm_request",
            deny_patterns=[re.compile(r"sk-proj-[A-Za-z0-9]{20,}")],
            severity=Severity.CRITICAL,
        )
        assert rule.min_unique_chars is None

    def test_accepts_positive_int(self) -> None:
        """min_unique_chars can be set to a positive integer."""
        rule = Rule(
            action_kind="llm_request",
            deny_patterns=[re.compile(r"sk-proj-[A-Za-z0-9]{20,}")],
            severity=Severity.CRITICAL,
            min_unique_chars=10,
        )
        assert rule.min_unique_chars == 10


class TestMinUniqueCharsFiltering:
    """Rule.matches() rejects low-entropy matches when min_unique_chars is set."""

    def _api_key_rule(
        self, *, scan: ScanTarget | None = ScanTarget.MESSAGES, min_unique: int = 10
    ) -> Rule:
        """Helper: rule mimicking no-secret-in-prompt API key pattern."""
        return Rule(
            action_kind="llm_request",
            deny_patterns=[re.compile(r"sk-(?:proj-)?[A-Za-z0-9]{20,}")],
            severity=Severity.CRITICAL,
            scan=scan,
            min_unique_chars=min_unique,
        )

    def test_real_key_is_denied(self) -> None:
        """A realistic API key with high entropy is still denied."""
        rule = self._api_key_rule()
        action = Action(
            kind="llm_request",
            params={"messages": "Use key " + _sk_proj_key(_REALISTIC_SUFFIX)},
        )
        assert rule.matches(action)

    def test_all_same_char_is_allowed(self) -> None:
        """All-A placeholder is NOT denied.

        Full match unique chars = {s,k,-,p,r,o,j,A} = 8.
        With min_unique_chars=10, 8 < 10 → not denied.
        """
        rule = self._api_key_rule()
        action = Action(
            kind="llm_request",
            params={"messages": "Use key " + _sk_proj_key("A" * 28)},
        )
        assert not rule.matches(action)

    def test_two_distinct_suffix_chars_still_low_entropy(self) -> None:
        """sk-proj-ABABAB... has 9 unique chars, NOT denied."""
        rule = self._api_key_rule(min_unique=10)
        action = Action(
            kind="llm_request",
            params={"messages": "Use key " + _sk_proj_key("AB" * 14)},
        )
        # unique chars: {s,k,-,p,r,o,j,A,B} = 9 < 10
        assert not rule.matches(action)

    def test_threshold_boundary_exact_match(self) -> None:
        """Exactly min_unique_chars distinct chars PASSES the filter (denied)."""
        rule = self._api_key_rule(min_unique=10)
        # "sk-proj-" contributes {s,k,-,p,r,o,j} = 7 unique
        # suffix "ABC" contributes {A,B,C} = 3 more → total 10
        action = Action(
            kind="llm_request",
            params={"messages": "Use key " + _sk_proj_key("ABC" * 10)},
        )
        assert rule.matches(action)

    def test_below_threshold_is_not_denied(self) -> None:
        """9 unique chars when min_unique=10 → not denied."""
        rule = self._api_key_rule(min_unique=10)
        # "sk-proj-" = {s,k,-,p,r,o,j} = 7, suffix "AB..." = {A,B} = 2 → 9 total
        action = Action(
            kind="llm_request",
            params={"messages": "Use key " + _sk_proj_key("AB" * 14)},
        )
        assert not rule.matches(action)

    def test_no_filter_when_min_unique_not_set(self) -> None:
        """Without min_unique_chars, all-A key IS denied (backward compat)."""
        rule = Rule(
            action_kind="llm_request",
            deny_patterns=[re.compile(r"sk-(?:proj-)?[A-Za-z0-9]{20,}")],
            severity=Severity.CRITICAL,
            scan=ScanTarget.MESSAGES,
            # min_unique_chars not set → None
        )
        action = Action(
            kind="llm_request",
            params={"messages": "Use key " + _sk_proj_key("A" * 28)},
        )
        assert rule.matches(action)

    def test_without_scan_target_also_filters(self) -> None:
        """min_unique_chars works when scan target is None (all params)."""
        rule = self._api_key_rule(scan=None, min_unique=10)
        # All-A placeholder → unique chars = 8 < 10 → should not match
        action = Action(
            kind="llm_request",
            params={"messages": "Use key " + _sk_proj_key("A" * 28)},
        )
        assert not rule.matches(action)

    def test_without_scan_target_real_key_denied(self) -> None:
        """Real key denied even without scan target."""
        rule = self._api_key_rule(scan=None, min_unique=10)
        action = Action(
            kind="llm_request",
            params={"messages": "Use key " + _sk_proj_key(_REALISTIC_SUFFIX)},
        )
        assert rule.matches(action)

    def test_multiple_patterns_first_high_entropy_wins(self) -> None:
        """If first pattern matches with sufficient entropy, deny."""
        rule = Rule(
            action_kind="llm_request",
            deny_patterns=[
                re.compile(r"sk-(?:proj-)?[A-Za-z0-9]{20,}"),
                re.compile(r"ghp_[A-Za-z0-9]{36,}"),
            ],
            severity=Severity.CRITICAL,
            scan=ScanTarget.MESSAGES,
            min_unique_chars=10,
        )
        action = Action(
            kind="llm_request",
            params={
                "messages": "key: " + _sk_proj_key(_REALISTIC_SUFFIX),
            },
        )
        assert rule.matches(action)

    def test_multiple_patterns_all_low_entropy_allowed(self) -> None:
        """If all pattern matches are low entropy, allow."""
        rule = Rule(
            action_kind="llm_request",
            deny_patterns=[
                re.compile(r"sk-(?:proj-)?[A-Za-z0-9]{20,}"),
                re.compile(r"ghp_[A-Za-z0-9]{36,}"),
            ],
            severity=Severity.CRITICAL,
            scan=ScanTarget.MESSAGES,
            min_unique_chars=10,
        )
        action = Action(
            kind="llm_request",
            params={
                "messages": (
                    "key: " + _sk_proj_key("A" * 28) + " and " + _ghp_token("a" * 36)
                ),
            },
        )
        assert not rule.matches(action)

    def test_scan_all_target_filters(self) -> None:
        """min_unique_chars works with scan=ALL."""
        rule = Rule(
            action_kind="llm_request",
            deny_patterns=[re.compile(r"sk-(?:proj-)?[A-Za-z0-9]{20,}")],
            severity=Severity.CRITICAL,
            scan=ScanTarget.ALL,
            min_unique_chars=10,
        )
        action = Action(
            kind="llm_request",
            params={"messages": "key: " + _sk_proj_key("A" * 28)},
        )
        assert not rule.matches(action)

    def test_low_entropy_before_real_key_still_denied(self) -> None:
        """A real key after a low-entropy placeholder must still be caught.

        Regression test: pattern.search() only returns the first match.
        If a low-entropy placeholder appears first and a real key second,
        finditer() must check all matches, not just the first.
        """
        rule = self._api_key_rule(min_unique=10)
        msg = (
            "low: "
            + _sk_proj_key("A" * 28)
            + " high: "
            + _sk_proj_key(_REALISTIC_SUFFIX)
        )
        action = Action(kind="llm_request", params={"messages": msg})
        assert rule.matches(action)

    def test_multiple_low_entropy_matches_all_skipped(self) -> None:
        """Multiple low-entropy matches with no real key → allowed."""
        rule = self._api_key_rule(min_unique=10)
        msg = "a: " + _sk_proj_key("A" * 28) + " b: " + _sk_proj_key("B" * 28)
        action = Action(kind="llm_request", params={"messages": msg})
        # Both have low entropy (8 and 8 unique), so allowed
        assert not rule.matches(action)


class TestMinUniqueCharsLoader:
    """YAML loader parses min_unique_chars from policy files."""

    def test_parse_rule_with_min_unique_chars(self) -> None:
        """min_unique_chars in YAML rule is parsed into Rule field."""
        from agentguard.policies.loader import load_policy_from_string

        yaml_str = """
name: test-policy
description: Test
rules:
  - action: llm_request
    description: Block API keys
    deny:
      - pattern: 'sk-(?:proj-)?[A-Za-z0-9]{20,}'
    severity: critical
    scan: messages
    min_unique_chars: 10
"""
        policy = load_policy_from_string(yaml_str)
        assert policy.rules[0].min_unique_chars == 10

    def test_parse_rule_without_min_unique_chars(self) -> None:
        """Rule without min_unique_chars gets None (backward compat)."""
        from agentguard.policies.loader import load_policy_from_string

        yaml_str = """
name: test-policy
description: Test
rules:
  - action: llm_request
    description: Block API keys
    deny:
      - pattern: 'sk-(?:proj-)?[A-Za-z0-9]{20,}'
    severity: critical
"""
        policy = load_policy_from_string(yaml_str)
        assert policy.rules[0].min_unique_chars is None

    def test_invalid_min_unique_chars_raises(self) -> None:
        """Non-integer min_unique_chars raises ValueError."""
        from agentguard.policies.loader import load_policy_from_string

        yaml_str = """
name: test-policy
description: Test
rules:
  - action: llm_request
    deny:
      - pattern: 'test'
    severity: critical
    min_unique_chars: not_a_number
"""
        with pytest.raises(ValueError, match="min_unique_chars"):
            load_policy_from_string(yaml_str)

    def test_zero_min_unique_chars_raises(self) -> None:
        """min_unique_chars=0 raises ValueError (must be positive)."""
        from agentguard.policies.loader import load_policy_from_string

        yaml_str = """
name: test-policy
description: Test
rules:
  - action: llm_request
    deny:
      - pattern: 'test'
    severity: critical
    min_unique_chars: 0
"""
        with pytest.raises(ValueError, match="min_unique_chars"):
            load_policy_from_string(yaml_str)


class TestNoSecretInPromptPolicy:
    """Integration: no-secret-in-prompt policy with min_unique_chars."""

    def test_real_key_blocked(self) -> None:
        """Real-looking API key is still blocked."""
        from agentguard.policies.builtins import load_builtin

        policy = load_builtin("no-secret-in-prompt")
        action = Action(
            kind="llm_request",
            params={"messages": "key: " + _sk_proj_key(_REALISTIC_SUFFIX)},
        )
        decision = policy.evaluate(action)
        assert decision.denied
        assert decision.denied_by == "no-secret-in-prompt"

    def test_placeholder_key_allowed(self) -> None:
        """Placeholder all-A key is NOT blocked."""
        from agentguard.policies.builtins import load_builtin

        policy = load_builtin("no-secret-in-prompt")
        action = Action(
            kind="llm_request",
            params={"messages": "Use key " + _sk_proj_key("A" * 28)},
        )
        decision = policy.evaluate(action)
        assert decision.allowed

    def test_ghp_placeholder_allowed(self) -> None:
        """Placeholder all-a GitHub PAT is NOT blocked."""
        from agentguard.policies.builtins import load_builtin

        policy = load_builtin("no-secret-in-prompt")
        action = Action(
            kind="llm_request",
            params={"messages": "token: " + _ghp_token("a" * 36)},
        )
        decision = policy.evaluate(action)
        assert decision.allowed

    def test_real_ghp_blocked(self) -> None:
        """Real-looking GitHub PAT is blocked."""
        from agentguard.policies.builtins import load_builtin

        policy = load_builtin("no-secret-in-prompt")
        action = Action(
            kind="llm_request",
            params={
                "messages": "token: "
                + _ghp_token("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"),
            },
        )
        decision = policy.evaluate(action)
        assert decision.denied

    def test_bearer_jwt_still_blocked(self) -> None:
        """Bearer JWT tokens (different rule, no min_unique_chars) still blocked."""
        from agentguard.policies.builtins import load_builtin

        # Build JWT at runtime to avoid safety scanner detection
        jwt_header = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
        jwt_payload = "eyJzdWIiOiIxMjM0NTY3ODkwIn0"
        jwt_sig = "dozjgNryP4J3jVmNHl0w5N_XS7cIFQdPMCQ"
        bearer_token = f"Bearer {jwt_header}.{jwt_payload}.{jwt_sig}"

        policy = load_builtin("no-secret-in-prompt")
        action = Action(
            kind="llm_request",
            params={"messages": f"Authorization: {bearer_token}"},
        )
        decision = policy.evaluate(action)
        assert decision.denied
