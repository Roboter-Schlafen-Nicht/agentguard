"""Tests for routing configuration dataclasses."""

from __future__ import annotations

import pytest


class TestModelTier:
    """Tests for ModelTier dataclass."""

    def test_minimal_tier(self) -> None:
        """ModelTier requires only name; model defaults to None."""
        from agentguard.proxy.routing.config import ModelTier

        tier = ModelTier(name="fast")
        assert tier.name == "fast"
        assert tier.model is None
        assert tier.upstream_url is None
        assert tier.max_tokens is None
        assert tier.max_messages is None
        assert tier.patterns == []

    def test_tier_with_model(self) -> None:
        """ModelTier with explicit model."""
        from agentguard.proxy.routing.config import ModelTier

        tier = ModelTier(name="fast", model="claude-sonnet-4")
        assert tier.name == "fast"
        assert tier.model == "claude-sonnet-4"

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

    def test_load_tier_without_model_defaults_to_none(self, tmp_path) -> None:
        """Tier without model field defaults to model=None."""
        from agentguard.proxy.routing.config import load_routing_config

        yaml_content = """\
enabled: true
tiers:
  - name: passthrough
"""
        config_file = tmp_path / "routing.yaml"
        config_file.write_text(yaml_content)

        config = load_routing_config(config_file)
        assert config.tiers[0].model is None

    def test_load_tier_with_null_model(self, tmp_path) -> None:
        """Tier with model: null is loaded as model=None."""
        from agentguard.proxy.routing.config import load_routing_config

        yaml_content = """\
enabled: true
tiers:
  - name: passthrough
    model: null
    max_tokens: 10000
  - name: premium
    model: claude-opus-4
"""
        config_file = tmp_path / "routing.yaml"
        config_file.write_text(yaml_content)

        config = load_routing_config(config_file)
        assert config.tiers[0].model is None
        assert config.tiers[0].max_tokens == 10000
        assert config.tiers[1].model == "claude-opus-4"


class TestModelTierDifficulty:
    """Tests for max_difficulty field on ModelTier."""

    def test_max_difficulty_default_is_none(self) -> None:
        """max_difficulty defaults to None."""
        from agentguard.proxy.routing.config import ModelTier

        tier = ModelTier(name="fast", model="claude-sonnet-4")
        assert tier.max_difficulty is None

    def test_max_difficulty_can_be_set(self) -> None:
        """max_difficulty can be set to an integer."""
        from agentguard.proxy.routing.config import ModelTier

        tier = ModelTier(
            name="fast",
            model="claude-sonnet-4",
            max_difficulty=1,
        )
        assert tier.max_difficulty == 1

    def test_max_difficulty_loaded_from_yaml(self, tmp_path) -> None:
        """max_difficulty is loaded from YAML config."""
        from agentguard.proxy.routing.config import load_routing_config

        yaml_content = """\
enabled: true
tiers:
  - name: fast
    model: claude-sonnet-4
    max_difficulty: 1
  - name: standard
    model: claude-sonnet-4
    max_difficulty: 2
  - name: premium
    model: claude-opus-4
"""
        config_file = tmp_path / "routing.yaml"
        config_file.write_text(yaml_content)

        config = load_routing_config(config_file)
        assert config.tiers[0].max_difficulty == 1
        assert config.tiers[1].max_difficulty == 2
        assert config.tiers[2].max_difficulty is None


class TestRoutingConfigClassifierUrl:
    """Tests for classifier_url field on RoutingConfig."""

    def test_classifier_url_default_is_empty(self) -> None:
        """classifier_url defaults to empty string."""
        from agentguard.proxy.routing.config import RoutingConfig

        config = RoutingConfig()
        assert config.classifier_url == ""

    def test_classifier_url_can_be_set(self) -> None:
        """classifier_url can be set."""
        from agentguard.proxy.routing.config import RoutingConfig

        config = RoutingConfig(
            classifier_url="http://localhost:11435",
        )
        assert config.classifier_url == "http://localhost:11435"

    def test_classifier_url_loaded_from_yaml(self, tmp_path) -> None:
        """classifier_url is loaded from YAML config."""
        from agentguard.proxy.routing.config import load_routing_config

        yaml_content = """\
enabled: true
classifier_url: http://localhost:11435
tiers:
  - name: default
    model: claude-sonnet-4
"""
        config_file = tmp_path / "routing.yaml"
        config_file.write_text(yaml_content)

        config = load_routing_config(config_file)
        assert config.classifier_url == "http://localhost:11435"


class TestRoutingConfigClassifierWindow:
    """Tests for classifier_window field on RoutingConfig."""

    def test_classifier_window_default_is_five(self) -> None:
        """classifier_window defaults to 5."""
        from agentguard.proxy.routing.config import RoutingConfig

        config = RoutingConfig()
        assert config.classifier_window == 5

    def test_classifier_window_can_be_set(self) -> None:
        """classifier_window can be set to a custom value."""
        from agentguard.proxy.routing.config import RoutingConfig

        config = RoutingConfig(classifier_window=10)
        assert config.classifier_window == 10

    def test_classifier_window_loaded_from_yaml(self, tmp_path) -> None:
        """classifier_window is loaded from YAML config."""
        from agentguard.proxy.routing.config import load_routing_config

        yaml_content = """\
enabled: true
classifier_window: 3
tiers:
  - name: default
    model: claude-sonnet-4
"""
        config_file = tmp_path / "routing.yaml"
        config_file.write_text(yaml_content)

        config = load_routing_config(config_file)
        assert config.classifier_window == 3

    def test_classifier_window_default_when_not_in_yaml(self, tmp_path) -> None:
        """classifier_window defaults to 5 when not in YAML."""
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
        assert config.classifier_window == 5
