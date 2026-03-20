"""Tests for routing CLI integration."""

from __future__ import annotations

import pytest


class TestBuildRoutingConfig:
    """Tests for _build_routing_config CLI helper."""

    def test_returns_none_without_flag(self) -> None:
        """No --routing-config flag returns None."""
        import argparse

        from agentguard.cli import _build_routing_config

        args = argparse.Namespace(routing_config=None)
        assert _build_routing_config(args) is None

    def test_loads_config_from_yaml(self, tmp_path) -> None:
        """--routing-config flag loads YAML file."""
        import argparse

        from agentguard.cli import _build_routing_config

        yaml_content = """\
enabled: true
default_tier: premium
tiers:
  - name: fast
    model: claude-sonnet-4
    max_tokens: 10000
  - name: premium
    model: claude-opus-4
"""
        config_file = tmp_path / "routing.yaml"
        config_file.write_text(yaml_content)

        args = argparse.Namespace(routing_config=str(config_file))
        config = _build_routing_config(args)

        assert config is not None
        assert config.enabled is True
        assert len(config.tiers) == 2
        assert config.tiers[0].name == "fast"
        assert config.tiers[1].name == "premium"

    def test_invalid_file_raises(self, tmp_path) -> None:
        """Invalid YAML file raises ValueError."""
        import argparse

        from agentguard.cli import _build_routing_config

        yaml_content = "enabled: [invalid"
        config_file = tmp_path / "routing.yaml"
        config_file.write_text(yaml_content)

        args = argparse.Namespace(routing_config=str(config_file))
        with pytest.raises(ValueError, match="Invalid YAML"):
            _build_routing_config(args)

    def test_missing_file_raises(self) -> None:
        """Missing file raises FileNotFoundError."""
        import argparse

        from agentguard.cli import _build_routing_config

        args = argparse.Namespace(routing_config="/nonexistent/routing.yaml")
        with pytest.raises(FileNotFoundError):
            _build_routing_config(args)


class TestClassifierUrlCLI:
    """Tests for --classifier-url CLI flag integration."""

    def test_classifier_url_wired_to_config(self, tmp_path) -> None:
        """--classifier-url is wired into RoutingConfig.classifier_url."""
        import argparse

        from agentguard.cli import _build_routing_config

        yaml_content = """\
enabled: true
tiers:
  - name: default
    model: claude-sonnet-4
"""
        config_file = tmp_path / "routing.yaml"
        config_file.write_text(yaml_content)

        args = argparse.Namespace(
            routing_config=str(config_file),
            classifier_url="http://localhost:11435",
        )
        config = _build_routing_config(args)

        assert config is not None
        assert config.classifier_url == "http://localhost:11435"

    def test_classifier_url_defaults_to_empty(self, tmp_path) -> None:
        """Without --classifier-url, classifier_url defaults to empty."""
        import argparse

        from agentguard.cli import _build_routing_config

        yaml_content = """\
enabled: true
tiers:
  - name: default
    model: claude-sonnet-4
"""
        config_file = tmp_path / "routing.yaml"
        config_file.write_text(yaml_content)

        args = argparse.Namespace(
            routing_config=str(config_file),
            classifier_url="",
        )
        config = _build_routing_config(args)

        assert config is not None
        assert config.classifier_url == ""
