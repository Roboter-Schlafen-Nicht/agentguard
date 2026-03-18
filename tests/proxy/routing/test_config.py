"""Tests for routing configuration dataclasses."""

from __future__ import annotations

import pytest


class TestModelTier:
    """Tests for ModelTier dataclass."""

    def test_minimal_tier(self) -> None:
        """ModelTier requires name and model."""
        from agentguard.proxy.routing.config import ModelTier

        tier = ModelTier(name="fast", model="claude-sonnet-4")
        assert tier.name == "fast"
        assert tier.model == "claude-sonnet-4"
        assert tier.upstream_url is None
        assert tier.max_tokens is None
        assert tier.max_messages is None
        assert tier.patterns == []

    def test_full_tier(self) -> None:
        """ModelTier with all fields set."""
        from agentguard.proxy.routing.config import ModelTier

        tier = ModelTier(
            name="premium",
            model="claude-opus-4",
            upstream_url="https://api.anthropic.com",
            max_tokens=50000,
            max_messages=100,
            patterns=["complex", "architect"],
        )
        assert tier.name == "premium"
        assert tier.model == "claude-opus-4"
        assert tier.upstream_url == "https://api.anthropic.com"
        assert tier.max_tokens == 50000
        assert tier.max_messages == 100
        assert tier.patterns == ["complex", "architect"]


class TestRoutingConfig:
    """Tests for RoutingConfig dataclass."""

    def test_disabled_by_default(self) -> None:
        """RoutingConfig is disabled by default."""
        from agentguard.proxy.routing.config import RoutingConfig

        config = RoutingConfig()
        assert config.enabled is False
        assert config.tiers == []
        assert config.default_tier == "default"

    def test_enabled_config(self) -> None:
        """RoutingConfig with tiers."""
        from agentguard.proxy.routing.config import ModelTier, RoutingConfig

        config = RoutingConfig(
            enabled=True,
            tiers=[
                ModelTier(name="fast", model="claude-sonnet-4", max_tokens=10000),
                ModelTier(name="premium", model="claude-opus-4"),
            ],
            default_tier="premium",
        )
        assert config.enabled is True
        assert len(config.tiers) == 2
        assert config.default_tier == "premium"


class TestRoutingConfigLoader:
    """Tests for loading RoutingConfig from YAML."""

    def test_load_from_yaml(self, tmp_path) -> None:
        """Load routing config from a YAML file."""
        from agentguard.proxy.routing.config import load_routing_config

        yaml_content = """\
enabled: true
default_tier: premium
tiers:
  - name: fast
    model: claude-sonnet-4
    max_tokens: 10000
    max_messages: 20
  - name: premium
    model: claude-opus-4
    upstream_url: https://api.anthropic.com
    patterns:
      - "architect"
      - "complex.*design"
"""
        config_file = tmp_path / "routing.yaml"
        config_file.write_text(yaml_content)

        config = load_routing_config(config_file)
        assert config.enabled is True
        assert config.default_tier == "premium"
        assert len(config.tiers) == 2
        assert config.tiers[0].name == "fast"
        assert config.tiers[0].max_tokens == 10000
        assert config.tiers[1].patterns == ["architect", "complex.*design"]

    def test_load_minimal_yaml(self, tmp_path) -> None:
        """Load minimal routing config from YAML."""
        from agentguard.proxy.routing.config import load_routing_config

        yaml_content = """\
enabled: true
tiers:
  - name: default
    model: claude-sonnet-4
"""
        config_file = tmp_path / "routing.yaml"
        config_file.write_text(yaml_content)

        config = load_routing_config(config_file)
        assert config.enabled is True
        assert len(config.tiers) == 1

    def test_load_invalid_yaml_raises(self, tmp_path) -> None:
        """Invalid YAML raises ValueError."""
        from agentguard.proxy.routing.config import load_routing_config

        yaml_content = "enabled: [invalid"
        config_file = tmp_path / "routing.yaml"
        config_file.write_text(yaml_content)

        with pytest.raises(ValueError, match="Invalid YAML"):
            load_routing_config(config_file)

    def test_load_missing_tiers_raises(self, tmp_path) -> None:
        """Missing tiers raises ValueError."""
        from agentguard.proxy.routing.config import load_routing_config

        yaml_content = """\
enabled: true
"""
        config_file = tmp_path / "routing.yaml"
        config_file.write_text(yaml_content)

        with pytest.raises(ValueError, match="tiers"):
            load_routing_config(config_file)

    def test_load_tier_missing_name_raises(self, tmp_path) -> None:
        """Tier without name raises ValueError."""
        from agentguard.proxy.routing.config import load_routing_config

        yaml_content = """\
enabled: true
tiers:
  - model: claude-sonnet-4
"""
        config_file = tmp_path / "routing.yaml"
        config_file.write_text(yaml_content)

        with pytest.raises(ValueError, match="name"):
            load_routing_config(config_file)

    def test_load_tier_missing_model_raises(self, tmp_path) -> None:
        """Tier without model raises ValueError."""
        from agentguard.proxy.routing.config import load_routing_config

        yaml_content = """\
enabled: true
tiers:
  - name: fast
"""
        config_file = tmp_path / "routing.yaml"
        config_file.write_text(yaml_content)

        with pytest.raises(ValueError, match="model"):
            load_routing_config(config_file)
