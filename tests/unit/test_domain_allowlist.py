"""Tests for domain allowlist policy type (M12).

Covers:
- DomainAllowlist creation and configuration
- Exact domain matching
- Wildcard subdomain matching (*.example.com)
- Preset loading (github, google, etc.)
- URL parsing to extract domain
- Deny for unlisted domains
- Allow for listed domains
- Multiple domains
- Guard integration
- YAML loading of domain allowlist policies
"""

from __future__ import annotations

import pytest

from agentguard.policies.domain_allowlist import (
    PRESETS,
    DomainAllowlist,
)
from agentguard.policies.guard import Guard
from agentguard.policies.loader import load_policy_from_string

# --- DomainAllowlist creation ---


class TestDomainAllowlistCreation:
    """Tests for DomainAllowlist initialization."""

    def test_create_with_domains(self) -> None:
        al = DomainAllowlist(
            name="test",
            domains=["example.com", "api.example.com"],
        )
        assert al.name == "test"

    def test_create_with_wildcard(self) -> None:
        al = DomainAllowlist(
            name="test",
            domains=["*.example.com"],
        )
        assert al.name == "test"

    def test_create_with_preset(self) -> None:
        al = DomainAllowlist(
            name="test",
            presets=["github"],
        )
        assert al.name == "test"

    def test_empty_domains_and_presets_raises(self) -> None:
        with pytest.raises(ValueError, match=r"domains.*presets"):
            DomainAllowlist(name="test")

    def test_unknown_preset_raises(self) -> None:
        with pytest.raises(ValueError, match="unknown_preset"):
            DomainAllowlist(name="test", presets=["unknown_preset"])


# --- Domain matching ---


class TestDomainMatching:
    """Tests for domain allowlist matching."""

    def test_exact_domain_allowed(self) -> None:
        al = DomainAllowlist(
            name="test",
            domains=["example.com"],
        )
        decision = al.evaluate_domain("example.com")
        assert decision.allowed is True

    def test_unlisted_domain_denied(self) -> None:
        al = DomainAllowlist(
            name="test",
            domains=["example.com"],
        )
        decision = al.evaluate_domain("evil.com")
        assert decision.denied is True
        assert decision.denied_by == "test"

    def test_wildcard_matches_subdomain(self) -> None:
        al = DomainAllowlist(
            name="test",
            domains=["*.example.com"],
        )
        decision = al.evaluate_domain("api.example.com")
        assert decision.allowed is True

    def test_wildcard_matches_nested_subdomain(self) -> None:
        al = DomainAllowlist(
            name="test",
            domains=["*.example.com"],
        )
        decision = al.evaluate_domain("v2.api.example.com")
        assert decision.allowed is True

    def test_wildcard_does_not_match_root(self) -> None:
        """*.example.com should NOT match example.com itself."""
        al = DomainAllowlist(
            name="test",
            domains=["*.example.com"],
        )
        decision = al.evaluate_domain("example.com")
        assert decision.denied is True

    def test_both_root_and_wildcard(self) -> None:
        al = DomainAllowlist(
            name="test",
            domains=["example.com", "*.example.com"],
        )
        assert al.evaluate_domain("example.com").allowed is True
        assert al.evaluate_domain("api.example.com").allowed is True

    def test_case_insensitive(self) -> None:
        al = DomainAllowlist(
            name="test",
            domains=["Example.COM"],
        )
        assert al.evaluate_domain("example.com").allowed is True
        assert al.evaluate_domain("EXAMPLE.COM").allowed is True

    def test_multiple_domains(self) -> None:
        al = DomainAllowlist(
            name="test",
            domains=["github.com", "api.github.com", "pypi.org"],
        )
        assert al.evaluate_domain("github.com").allowed is True
        assert al.evaluate_domain("api.github.com").allowed is True
        assert al.evaluate_domain("pypi.org").allowed is True
        assert al.evaluate_domain("evil.com").denied is True


# --- URL parsing ---


class TestURLParsing:
    """Tests for extracting domains from URLs."""

    def test_extract_domain_from_https_url(self) -> None:
        al = DomainAllowlist(
            name="test",
            domains=["example.com"],
        )
        decision = al.evaluate_url("https://example.com/path")
        assert decision.allowed is True

    def test_extract_domain_from_http_url(self) -> None:
        al = DomainAllowlist(
            name="test",
            domains=["example.com"],
        )
        decision = al.evaluate_url("http://example.com/page")
        assert decision.allowed is True

    def test_url_with_port(self) -> None:
        al = DomainAllowlist(
            name="test",
            domains=["example.com"],
        )
        decision = al.evaluate_url("https://example.com:8080/api")
        assert decision.allowed is True

    def test_url_with_auth(self) -> None:
        al = DomainAllowlist(
            name="test",
            domains=["example.com"],
        )
        decision = al.evaluate_url("https://user:pass@example.com/path")
        assert decision.allowed is True

    def test_invalid_url_denied(self) -> None:
        al = DomainAllowlist(
            name="test",
            domains=["example.com"],
        )
        decision = al.evaluate_url("not-a-url")
        assert decision.denied is True


# --- Presets ---


class TestPresets:
    """Tests for built-in domain presets."""

    def test_github_preset_exists(self) -> None:
        assert "github" in PRESETS

    def test_google_preset_exists(self) -> None:
        assert "google" in PRESETS

    def test_preset_domains_are_lists(self) -> None:
        for name, domains in PRESETS.items():
            assert isinstance(domains, list), f"Preset '{name}' is not a list"
            assert len(domains) > 0, f"Preset '{name}' is empty"

    def test_github_preset_includes_expected_domains(self) -> None:
        al = DomainAllowlist(name="test", presets=["github"])
        assert al.evaluate_domain("github.com").allowed is True
        assert al.evaluate_domain("api.github.com").allowed is True

    def test_combined_presets_and_domains(self) -> None:
        al = DomainAllowlist(
            name="test",
            domains=["custom.internal.com"],
            presets=["github"],
        )
        assert al.evaluate_domain("github.com").allowed is True
        assert al.evaluate_domain("custom.internal.com").allowed is True
        assert al.evaluate_domain("evil.com").denied is True


# --- Guard integration via evaluate() ---


class TestGuardIntegration:
    """Tests for DomainAllowlist as a Policy in Guard."""

    def test_domain_policy_in_guard(self) -> None:
        al = DomainAllowlist(
            name="domain-guard",
            domains=["safe.com"],
            action_kind="web_request",
        )
        guard = Guard(policies=[al])

        # Allowed domain
        decision = guard.check("web_request", url="https://safe.com/api")
        assert decision.allowed is True

        # Denied domain
        decision = guard.check("web_request", url="https://evil.com/steal")
        assert decision.denied is True
        assert decision.denied_by == "domain-guard"

    def test_non_matching_action_kind_passes(self) -> None:
        """DomainAllowlist only applies to its configured action kind."""
        al = DomainAllowlist(
            name="domain-guard",
            domains=["safe.com"],
            action_kind="web_request",
        )
        guard = Guard(policies=[al])

        # Different action kind should pass
        decision = guard.check("shell_command", command="echo hello")
        assert decision.allowed is True

    def test_action_with_domain_param(self) -> None:
        """Support checking 'domain' param directly."""
        al = DomainAllowlist(
            name="domain-guard",
            domains=["api.example.com"],
            action_kind="api_call",
        )
        guard = Guard(policies=[al])

        decision = guard.check("api_call", domain="api.example.com")
        assert decision.allowed is True

        decision = guard.check("api_call", domain="evil.com")
        assert decision.denied is True


# --- YAML loading ---


class TestYAMLLoading:
    """Tests for loading domain allowlist from YAML."""

    def test_load_domain_allowlist_from_yaml(self) -> None:
        yaml_str = """
name: web-access
type: domain_allowlist
action: web_request
domains:
  - example.com
  - "*.example.com"
  - api.github.com
"""
        policy = load_policy_from_string(yaml_str)
        assert isinstance(policy, DomainAllowlist)
        assert policy.name == "web-access"

    def test_load_with_presets(self) -> None:
        yaml_str = """
name: with-presets
type: domain_allowlist
action: web_request
presets:
  - github
  - google
"""
        policy = load_policy_from_string(yaml_str)
        assert isinstance(policy, DomainAllowlist)

    def test_load_with_domains_and_presets(self) -> None:
        yaml_str = """
name: combined
type: domain_allowlist
action: web_request
domains:
  - custom.internal.com
presets:
  - github
"""
        policy = load_policy_from_string(yaml_str)
        assert isinstance(policy, DomainAllowlist)

    def test_yaml_domain_allowlist_in_guard(self) -> None:
        yaml_str = """
name: web-guard
type: domain_allowlist
action: web_request
domains:
  - safe.example.com
"""
        guard = Guard()
        guard.load_policy_string(yaml_str)

        decision = guard.check("web_request", url="https://safe.example.com/api")
        assert decision.allowed is True

        decision = guard.check("web_request", url="https://evil.com/steal")
        assert decision.denied is True
