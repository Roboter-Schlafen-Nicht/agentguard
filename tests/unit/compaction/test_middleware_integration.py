"""Tests for compaction integration in proxy middleware.

Tests cover:
- Middleware applies compaction when enabled
- Middleware forwards compacted body to upstream
- Compaction metrics appear in audit log
- Disabled compaction passes through unchanged
- CLI flags for compaction
"""

from __future__ import annotations

import json

import pytest

from agentguard.proxy.compaction.config import CompactionConfig
from agentguard.proxy.config import ProxyConfig


def _make_request_body(turns: int = 20, lines_per_tool: int = 50) -> bytes:
    """Build a JSON request body with messages."""
    messages: list[dict] = [{"role": "system", "content": "You are an assistant."}]

    for i in range(turns):
        messages.append({"role": "user", "content": f"User message {i}"})
        tool_call_id = f"call_{i}"
        messages.append(
            {
                "role": "assistant",
                "content": None,
                "tool_calls": [
                    {
                        "id": tool_call_id,
                        "type": "function",
                        "function": {
                            "name": "bash",
                            "arguments": f'{{"command": "cmd_{i}"}}',
                        },
                    }
                ],
            }
        )
        tool_lines = [f"output line {j} of turn {i}" for j in range(lines_per_tool)]
        messages.append(
            {
                "role": "tool",
                "tool_call_id": tool_call_id,
                "content": "\n".join(tool_lines),
            }
        )
        messages.append({"role": "assistant", "content": f"Done with turn {i}."})

    body = {"model": "test-model", "messages": messages}
    return json.dumps(body).encode("utf-8")


class TestProxyConfigCompaction:
    """Test compaction field on ProxyConfig."""

    def test_compaction_field_exists(self):
        """ProxyConfig accepts a compaction field."""
        config = ProxyConfig(
            upstream_base_url="https://api.example.com",
            compaction=CompactionConfig(enabled=True, token_budget=20_000),
        )
        assert config.compaction is not None
        assert config.compaction.enabled is True
        assert config.compaction.token_budget == 20_000

    def test_compaction_default_none(self):
        """Compaction defaults to None for backward compatibility."""
        config = ProxyConfig(upstream_base_url="https://api.example.com")
        assert config.compaction is None


class TestMiddlewareCompaction:
    """Test compaction in the GuardMiddleware."""

    def test_middleware_has_compaction_engine(self):
        """Middleware creates a CompactionEngine when compaction is configured."""
        from agentguard.proxy.middleware import GuardMiddleware

        config = ProxyConfig(
            upstream_base_url="https://api.example.com",
            compaction=CompactionConfig(enabled=True),
        )
        mw = GuardMiddleware(config)
        assert hasattr(mw, "compaction_engine")
        assert mw.compaction_engine is not None

    def test_middleware_no_compaction_engine_when_not_configured(self):
        """Middleware has no compaction engine when not configured."""
        from agentguard.proxy.middleware import GuardMiddleware

        config = ProxyConfig(upstream_base_url="https://api.example.com")
        mw = GuardMiddleware(config)
        assert mw.compaction_engine is None

    @pytest.mark.asyncio
    async def test_compaction_modifies_forwarded_body(self):
        """When compaction is enabled, the forwarded body has fewer tokens."""
        from agentguard.proxy.middleware import GuardMiddleware

        config = ProxyConfig(
            upstream_base_url="https://api.example.com",
            compaction=CompactionConfig(
                enabled=True,
                token_budget=5000,
                recent_turns=3,
                truncate_after_turns=3,
                stub_after_turns=8,
                keep_lines=2,
            ),
        )
        mw = GuardMiddleware(config)

        original_body = _make_request_body(turns=20, lines_per_tool=50)

        # Use the compact_body method directly
        compacted_body, metrics = await mw._compact_request_body(original_body)
        json.loads(compacted_body)  # ensure valid JSON

        # Should have fewer messages or shorter content
        assert metrics["tokens_before"] > metrics["tokens_after"]
        assert metrics["phase_used"] != "disabled"

    @pytest.mark.asyncio
    async def test_compaction_disabled_passes_through(self):
        """Disabled compaction returns body unchanged."""
        from agentguard.proxy.middleware import GuardMiddleware

        config = ProxyConfig(
            upstream_base_url="https://api.example.com",
            compaction=CompactionConfig(enabled=False),
        )
        mw = GuardMiddleware(config)

        body = _make_request_body(turns=5, lines_per_tool=10)
        compacted_body, metrics = await mw._compact_request_body(body)

        assert compacted_body == body
        assert metrics["phase_used"] == "disabled"

    @pytest.mark.asyncio
    async def test_no_compaction_config_passes_through(self):
        """No compaction config returns body unchanged."""
        from agentguard.proxy.middleware import GuardMiddleware

        config = ProxyConfig(upstream_base_url="https://api.example.com")
        mw = GuardMiddleware(config)

        body = _make_request_body(turns=5, lines_per_tool=10)
        compacted_body, metrics = await mw._compact_request_body(body)

        assert compacted_body == body
        assert metrics["phase_used"] == "disabled"


class TestCLICompactionFlags:
    """Test CLI argument parsing for compaction flags."""

    def test_compaction_flag_enables_compaction(self):
        """--compaction flag is parsed and creates enabled CompactionConfig."""
        from agentguard.cli import _build_parser

        parser = _build_parser()
        args = parser.parse_args(["proxy", "https://api.example.com", "--compaction"])
        assert args.compaction is True

    def test_compaction_budget_flag(self):
        """--compaction-budget sets the token budget."""
        from agentguard.cli import _build_parser

        parser = _build_parser()
        args = parser.parse_args(
            [
                "proxy",
                "https://api.example.com",
                "--compaction",
                "--compaction-budget",
                "20000",
            ]
        )
        assert args.compaction_budget == 20000

    def test_compaction_model_flag(self):
        """--compaction-model sets the summarizer model."""
        from agentguard.cli import _build_parser

        parser = _build_parser()
        args = parser.parse_args(
            [
                "proxy",
                "https://api.example.com",
                "--compaction",
                "--compaction-model",
                "qwen2:7b",
            ]
        )
        assert args.compaction_model == "qwen2:7b"

    def test_compaction_url_flag(self):
        """--compaction-url sets the summarizer URL."""
        from agentguard.cli import _build_parser

        parser = _build_parser()
        args = parser.parse_args(
            [
                "proxy",
                "https://api.example.com",
                "--compaction",
                "--compaction-url",
                "http://localhost:11435",
            ]
        )
        assert args.compaction_url == "http://localhost:11435"

    def test_compaction_defaults(self):
        """Default values when --compaction is not set."""
        from agentguard.cli import _build_parser

        parser = _build_parser()
        args = parser.parse_args(["proxy", "https://api.example.com"])
        assert args.compaction is False
        assert args.compaction_budget == 30000
        assert args.compaction_model == "rnj-1:8b-16k"
        assert args.compaction_url == "http://localhost:11434"

    def test_build_compaction_config_from_args(self):
        """_build_compaction_config creates CompactionConfig from CLI args."""
        from agentguard.cli import _build_compaction_config, _build_parser

        parser = _build_parser()
        args = parser.parse_args(
            [
                "proxy",
                "https://api.example.com",
                "--compaction",
                "--compaction-budget",
                "25000",
                "--compaction-model",
                "qwen2:7b",
                "--compaction-url",
                "http://localhost:11435",
            ]
        )
        config = _build_compaction_config(args)
        assert config is not None
        assert config.enabled is True
        assert config.token_budget == 25000
        assert config.summarizer_model == "qwen2:7b"
        assert config.summarizer_url == "http://localhost:11435"

    def test_build_compaction_config_none_when_disabled(self):
        """_build_compaction_config returns None when --compaction not set."""
        from agentguard.cli import _build_compaction_config, _build_parser

        parser = _build_parser()
        args = parser.parse_args(["proxy", "https://api.example.com"])
        config = _build_compaction_config(args)
        assert config is None
