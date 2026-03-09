"""Tests for ProxyConfig dataclass."""

from __future__ import annotations

import pytest

from agentguard.proxy.config import ProxyConfig


class TestProxyConfigDefaults:
    """Test default values and basic construction."""

    def test_minimal_config(self) -> None:
        """Config with only upstream_base_url should use defaults."""
        cfg = ProxyConfig(upstream_base_url="https://api.openai.com")
        assert cfg.upstream_base_url == "https://api.openai.com"
        assert cfg.host == "127.0.0.1"
        assert cfg.port == 8080
        assert cfg.policy_dir is None
        assert cfg.audit_dir is None
        assert cfg.actor == "llm-proxy"
        assert cfg.load_builtins is False
        assert cfg.auto_discover is False
        assert cfg.scan_responses is False
        assert cfg.timeout == 120.0
        assert cfg.allowed_endpoints == []

    def test_all_fields_set(self) -> None:
        """Config with all fields explicitly set."""
        cfg = ProxyConfig(
            upstream_base_url="https://api.anthropic.com",
            host="0.0.0.0",
            port=9090,
            policy_dir="/tmp/policies",
            audit_dir="/tmp/audit",
            actor="my-agent",
            load_builtins=True,
            auto_discover=True,
            scan_responses=True,
            timeout=60.0,
            allowed_endpoints=["/v1/chat/completions"],
        )
        assert cfg.upstream_base_url == "https://api.anthropic.com"
        assert cfg.host == "0.0.0.0"
        assert cfg.port == 9090
        assert cfg.policy_dir == "/tmp/policies"
        assert cfg.audit_dir == "/tmp/audit"
        assert cfg.actor == "my-agent"
        assert cfg.load_builtins is True
        assert cfg.auto_discover is True
        assert cfg.scan_responses is True
        assert cfg.timeout == 60.0
        assert cfg.allowed_endpoints == ["/v1/chat/completions"]


class TestProxyConfigValidation:
    """Test validation in __post_init__."""

    def test_trailing_slash_stripped(self) -> None:
        """Trailing slash on upstream_base_url should be stripped."""
        cfg = ProxyConfig(upstream_base_url="https://api.openai.com/")
        assert cfg.upstream_base_url == "https://api.openai.com"

    def test_multiple_trailing_slashes_stripped(self) -> None:
        """Multiple trailing slashes should all be stripped."""
        cfg = ProxyConfig(upstream_base_url="https://api.openai.com///")
        assert cfg.upstream_base_url == "https://api.openai.com"

    def test_empty_upstream_url_raises(self) -> None:
        """Empty upstream_base_url should raise ValueError."""
        with pytest.raises(ValueError, match="upstream_base_url is required"):
            ProxyConfig(upstream_base_url="")

    def test_invalid_port_zero_raises(self) -> None:
        """Port 0 should raise ValueError."""
        with pytest.raises(ValueError, match="port must be 1-65535"):
            ProxyConfig(upstream_base_url="https://api.openai.com", port=0)

    def test_invalid_port_too_high_raises(self) -> None:
        """Port > 65535 should raise ValueError."""
        with pytest.raises(ValueError, match="port must be 1-65535"):
            ProxyConfig(upstream_base_url="https://api.openai.com", port=70000)

    def test_negative_timeout_raises(self) -> None:
        """Negative timeout should raise ValueError."""
        with pytest.raises(ValueError, match="timeout must be positive"):
            ProxyConfig(upstream_base_url="https://api.openai.com", timeout=-1)

    def test_zero_timeout_raises(self) -> None:
        """Zero timeout should raise ValueError."""
        with pytest.raises(ValueError, match="timeout must be positive"):
            ProxyConfig(upstream_base_url="https://api.openai.com", timeout=0)

    def test_valid_port_boundaries(self) -> None:
        """Ports 1 and 65535 should be valid."""
        cfg1 = ProxyConfig(upstream_base_url="https://api.openai.com", port=1)
        assert cfg1.port == 1
        cfg2 = ProxyConfig(upstream_base_url="https://api.openai.com", port=65535)
        assert cfg2.port == 65535


class TestProxyConfigAllowedEndpoints:
    """Test allowed_endpoints behavior."""

    def test_default_empty_list_not_shared(self) -> None:
        """Each config should get its own list instance."""
        cfg1 = ProxyConfig(upstream_base_url="https://api.openai.com")
        cfg2 = ProxyConfig(upstream_base_url="https://api.openai.com")
        cfg1.allowed_endpoints.append("/v1/test")
        assert cfg2.allowed_endpoints == []
