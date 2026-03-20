"""Tests for structured logging in the routing module.

Covers:
- Structured logging on routing decisions (INFO for matches, DEBUG for
  disabled/passthrough, WARNING for default-tier-not-found fallback)
- RoutingConfig.log_dir field (CLI-only, empty default)
- configure_routing_logging() FileHandler wiring
- --routing-log-dir CLI argument
- configure_routing_logging() called from _cmd_proxy()
"""

from __future__ import annotations

import logging
import os
import tempfile

from agentguard.proxy.routing.config import ModelTier, RoutingConfig


def _two_tier_config(*, enabled: bool = True) -> RoutingConfig:
    """Build a simple two-tier routing config for tests."""
    return RoutingConfig(
        enabled=enabled,
        tiers=[
            ModelTier(name="fast", model="claude-sonnet-4", max_tokens=10000),
            ModelTier(name="premium", model="claude-opus-4"),
        ],
        default_tier="premium",
    )


class TestRouterLogging:
    """Verify structured logging is emitted by the Router."""

    def test_logs_debug_when_disabled(self, caplog) -> None:
        """Router logs DEBUG when routing is disabled."""
        from agentguard.proxy.routing.router import Router

        config = _two_tier_config(enabled=False)
        router = Router(config)

        with caplog.at_level(logging.DEBUG, logger="agentguard.proxy.routing.router"):
            router.route(token_estimate=1000, message_count=5, content="hello")

        debug_records = [
            r
            for r in caplog.records
            if r.levelno == logging.DEBUG
            and "agentguard.proxy.routing.router" in r.name
        ]
        assert len(debug_records) >= 1, (
            f"Expected DEBUG log when routing disabled, got: {caplog.text}"
        )
        log_text = " ".join(r.getMessage() for r in debug_records)
        assert "disabled" in log_text.lower() or "passthrough" in log_text.lower()

    def test_logs_info_on_tier_match(self, caplog) -> None:
        """Router logs INFO when a tier matches."""
        from agentguard.proxy.routing.router import Router

        config = _two_tier_config()
        router = Router(config)

        with caplog.at_level(logging.INFO, logger="agentguard.proxy.routing.router"):
            router.route(token_estimate=5000, message_count=5, content="hello")

        info_records = [
            r
            for r in caplog.records
            if r.levelno == logging.INFO and "agentguard.proxy.routing.router" in r.name
        ]
        assert len(info_records) >= 1, (
            f"Expected INFO log on tier match, got: {caplog.text}"
        )
        log_text = " ".join(r.getMessage() for r in info_records)
        # Should mention the tier name and model
        assert "fast" in log_text
        assert "claude-sonnet-4" in log_text

    def test_info_log_contains_structured_metrics(self, caplog) -> None:
        """Routing INFO log includes token estimate and message count."""
        from agentguard.proxy.routing.router import Router

        config = _two_tier_config()
        router = Router(config)

        with caplog.at_level(logging.INFO, logger="agentguard.proxy.routing.router"):
            router.route(token_estimate=7500, message_count=12, content="test")

        info_records = [
            r
            for r in caplog.records
            if r.levelno == logging.INFO and "agentguard.proxy.routing.router" in r.name
        ]
        assert len(info_records) >= 1
        log_text = " ".join(r.getMessage() for r in info_records)
        # Structured key=value format
        assert "tokens=" in log_text or "token_estimate=" in log_text
        assert "messages=" in log_text or "message_count=" in log_text

    def test_logs_info_on_default_tier_fallback(self, caplog) -> None:
        """Router logs INFO when falling back to default tier."""
        from agentguard.proxy.routing.router import Router

        config = RoutingConfig(
            enabled=True,
            tiers=[
                ModelTier(name="fast", model="claude-sonnet-4", max_tokens=1000),
            ],
            default_tier="fast",
        )
        router = Router(config)

        with caplog.at_level(logging.INFO, logger="agentguard.proxy.routing.router"):
            # Exceeds all thresholds — falls back to default
            router.route(token_estimate=50000, message_count=100, content="big request")

        info_records = [
            r
            for r in caplog.records
            if r.levelno == logging.INFO and "agentguard.proxy.routing.router" in r.name
        ]
        assert len(info_records) >= 1, (
            f"Expected INFO log on default fallback, got: {caplog.text}"
        )
        log_text = " ".join(r.getMessage() for r in info_records)
        assert "default" in log_text.lower()

    def test_logs_warning_when_default_tier_not_found(self, caplog) -> None:
        """Router logs WARNING when default_tier name doesn't match any tier."""
        from agentguard.proxy.routing.router import Router

        config = RoutingConfig(
            enabled=True,
            tiers=[
                ModelTier(name="fast", model="claude-sonnet-4", max_tokens=1000),
                ModelTier(
                    name="premium",
                    model="claude-opus-4",
                    max_tokens=2000,
                ),
            ],
            default_tier="nonexistent",
        )
        router = Router(config)

        with caplog.at_level(logging.WARNING, logger="agentguard.proxy.routing.router"):
            # Token estimate exceeds all tiers' max_tokens
            router.route(token_estimate=50000, message_count=100, content="big")
        router = Router(config)

        with caplog.at_level(logging.WARNING, logger="agentguard.proxy.routing.router"):
            router.route(token_estimate=50000, message_count=100, content="big")

        warn_records = [
            r
            for r in caplog.records
            if r.levelno == logging.WARNING
            and "agentguard.proxy.routing.router" in r.name
        ]
        assert len(warn_records) >= 1, (
            f"Expected WARNING when default tier not found, got: {caplog.text}"
        )
        warn_text = " ".join(r.getMessage() for r in warn_records)
        assert "nonexistent" in warn_text

    def test_logs_warning_when_no_tiers_configured(self, caplog) -> None:
        """Router logs WARNING when no tiers exist at all."""
        from agentguard.proxy.routing.router import Router

        # RoutingConfig with empty tiers requires building manually
        # since load_routing_config validates tiers
        config = RoutingConfig(enabled=True, tiers=[], default_tier="default")
        router = Router(config)

        with caplog.at_level(logging.WARNING, logger="agentguard.proxy.routing.router"):
            router.route(token_estimate=1000, message_count=5, content="test")

        warn_records = [
            r
            for r in caplog.records
            if r.levelno == logging.WARNING
            and "agentguard.proxy.routing.router" in r.name
        ]
        assert len(warn_records) >= 1, (
            f"Expected WARNING when no tiers configured, got: {caplog.text}"
        )

    def test_logs_pattern_match_detail(self, caplog) -> None:
        """Router INFO log mentions pattern match when that's the trigger."""
        from agentguard.proxy.routing.router import Router

        config = RoutingConfig(
            enabled=True,
            tiers=[
                ModelTier(
                    name="premium",
                    model="claude-opus-4",
                    patterns=["architect"],
                ),
                ModelTier(name="standard", model="claude-sonnet-4"),
            ],
            default_tier="standard",
        )
        router = Router(config)

        with caplog.at_level(logging.INFO, logger="agentguard.proxy.routing.router"):
            router.route(
                token_estimate=1000,
                message_count=5,
                content="help me architect a system",
            )

        info_records = [
            r
            for r in caplog.records
            if r.levelno == logging.INFO and "agentguard.proxy.routing.router" in r.name
        ]
        assert len(info_records) >= 1
        log_text = " ".join(r.getMessage() for r in info_records)
        assert "premium" in log_text
        assert "pattern" in log_text.lower()


class TestRoutingLogDirConfig:
    """Verify RoutingConfig.log_dir field."""

    def test_log_dir_default_is_empty_string(self) -> None:
        """RoutingConfig log_dir defaults to empty string (no logging)."""
        config = RoutingConfig()
        assert config.log_dir == ""

    def test_log_dir_custom(self) -> None:
        """RoutingConfig accepts a custom log_dir."""
        config = RoutingConfig(log_dir="/tmp/routing-logs/")
        assert config.log_dir == "/tmp/routing-logs/"

    def test_load_routing_config_preserves_log_dir(self, tmp_path) -> None:
        """log_dir is preserved through YAML load (uses default empty)."""
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
        assert config.log_dir == ""


class TestRoutingFileHandlerWiring:
    """Verify configure_routing_logging FileHandler setup."""

    def test_configure_routing_logging_creates_handler(self) -> None:
        """configure_routing_logging adds FileHandler when log_dir is set."""
        from agentguard.proxy.routing.config import configure_routing_logging

        with tempfile.TemporaryDirectory() as tmpdir:
            config = RoutingConfig(log_dir=tmpdir)
            handler = configure_routing_logging(config)

            assert handler is not None
            assert isinstance(handler, logging.FileHandler)

            # Verify the file was created in the right directory
            assert tmpdir in handler.baseFilename
            assert "routing.log" in handler.baseFilename

            # Clean up
            handler.close()
            log = logging.getLogger("agentguard.proxy.routing")
            log.removeHandler(handler)

    def test_configure_routing_logging_sets_logger_level(self) -> None:
        """configure_routing_logging sets logger level to DEBUG."""
        from agentguard.proxy.routing.config import configure_routing_logging

        with tempfile.TemporaryDirectory() as tmpdir:
            config = RoutingConfig(log_dir=tmpdir)
            handler = configure_routing_logging(config)
            assert handler is not None

            log = logging.getLogger("agentguard.proxy.routing")
            assert log.level <= logging.DEBUG, (
                f"Logger level is {logging.getLevelName(log.level)}, "
                f"expected DEBUG or lower so INFO messages reach the handler"
            )

            assert log.isEnabledFor(logging.INFO), (
                "Logger should allow INFO messages for routing decision logging"
            )

            # Clean up
            handler.close()
            log.removeHandler(handler)
            log.setLevel(logging.NOTSET)

    def test_info_messages_reach_file_handler(self) -> None:
        """INFO-level messages from child loggers reach the routing log file."""
        from agentguard.proxy.routing.config import configure_routing_logging

        with tempfile.TemporaryDirectory() as tmpdir:
            config = RoutingConfig(log_dir=tmpdir)
            handler = configure_routing_logging(config)
            assert handler is not None

            # Simulate what router.py does
            child_logger = logging.getLogger("agentguard.proxy.routing.router")
            child_logger.info(
                "routing_decision tier=fast model=claude-sonnet-4 "
                "tokens=5000 messages=5"
            )

            handler.flush()

            log_path = os.path.join(tmpdir, "routing.log")
            with open(log_path) as f:
                content = f.read()
            assert "routing_decision" in content, (
                f"INFO message not found in routing.log. Content: {content!r}"
            )

            # Clean up
            handler.close()
            parent_log = logging.getLogger("agentguard.proxy.routing")
            parent_log.removeHandler(handler)
            parent_log.setLevel(logging.NOTSET)

    def test_configure_routing_logging_noop_when_empty(self) -> None:
        """configure_routing_logging returns None when log_dir is empty."""
        from agentguard.proxy.routing.config import configure_routing_logging

        config = RoutingConfig(log_dir="")
        handler = configure_routing_logging(config)
        assert handler is None

    def test_configure_routing_logging_creates_directory(self) -> None:
        """configure_routing_logging creates log_dir if it doesn't exist."""
        from agentguard.proxy.routing.config import configure_routing_logging

        with tempfile.TemporaryDirectory() as tmpdir:
            subdir = os.path.join(tmpdir, "nested", "routing-logs")
            config = RoutingConfig(log_dir=subdir)
            handler = configure_routing_logging(config)

            assert handler is not None
            assert os.path.isdir(subdir)

            # Clean up
            handler.close()
            log = logging.getLogger("agentguard.proxy.routing")
            log.removeHandler(handler)
            log.setLevel(logging.NOTSET)


class TestRoutingLogDirCLI:
    """Verify --routing-log-dir CLI argument."""

    def test_routing_log_dir_argument_exists(self) -> None:
        """CLI has --routing-log-dir argument."""
        from agentguard.cli import _build_parser

        parser = _build_parser()
        args = parser.parse_args(
            [
                "proxy",
                "https://api.example.com",
                "--routing-log-dir",
                "/tmp/routing-logs/",
            ]
        )
        assert args.routing_log_dir == "/tmp/routing-logs/"

    def test_routing_log_dir_default_is_empty(self) -> None:
        """--routing-log-dir defaults to empty string."""
        from agentguard.cli import _build_parser

        parser = _build_parser()
        args = parser.parse_args(["proxy", "https://api.example.com"])
        assert args.routing_log_dir == ""

    def test_build_routing_config_uses_routing_log_dir(self) -> None:
        """_build_routing_config reads routing_log_dir from args."""
        from agentguard.cli import _build_parser, _build_routing_config

        # Create a temporary routing config YAML
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write(
                "enabled: true\ntiers:\n  - name: default\n    model: claude-sonnet-4\n"
            )
            yaml_path = f.name

        try:
            parser = _build_parser()
            args = parser.parse_args(
                [
                    "proxy",
                    "https://api.example.com",
                    "--routing-config",
                    yaml_path,
                    "--routing-log-dir",
                    "/tmp/my-routing-logs/",
                ]
            )
            config = _build_routing_config(args)
            assert config is not None
            assert config.log_dir == "/tmp/my-routing-logs/"
        finally:
            os.unlink(yaml_path)

    def test_build_routing_config_default_log_dir(self) -> None:
        """_build_routing_config sets empty log_dir by default."""
        from agentguard.cli import _build_parser, _build_routing_config

        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write(
                "enabled: true\ntiers:\n  - name: default\n    model: claude-sonnet-4\n"
            )
            yaml_path = f.name

        try:
            parser = _build_parser()
            args = parser.parse_args(
                [
                    "proxy",
                    "https://api.example.com",
                    "--routing-config",
                    yaml_path,
                ]
            )
            config = _build_routing_config(args)
            assert config is not None
            assert config.log_dir == ""
        finally:
            os.unlink(yaml_path)


class TestRoutingLoggingWiring:
    """Verify configure_routing_logging is called from production code paths."""

    def test_cmd_proxy_calls_configure_routing_logging(self) -> None:
        """_cmd_proxy must call configure_routing_logging after building config."""
        import ast
        import inspect

        from agentguard.cli import _cmd_proxy

        source = inspect.getsource(_cmd_proxy)
        tree = ast.parse(source)

        # Walk the AST looking for a call to configure_routing_logging
        found = False
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func = node.func
                # Match both `configure_routing_logging(...)` and
                # `module.configure_routing_logging(...)`
                if (
                    isinstance(func, ast.Name)
                    and func.id == "configure_routing_logging"
                ):
                    found = True
                    break
                if (
                    isinstance(func, ast.Attribute)
                    and func.attr == "configure_routing_logging"
                ):
                    found = True
                    break

        assert found, (
            "configure_routing_logging() is not called in _cmd_proxy(). "
            "File logging will never activate at runtime even when "
            "--routing-log-dir is set."
        )
