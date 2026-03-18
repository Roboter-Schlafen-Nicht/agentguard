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
from typing import ClassVar

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


class TestHandleRequestCompaction:
    """Test handle_request() compaction wiring."""

    @pytest.mark.asyncio
    async def test_handle_request_forwards_compacted_body(self):
        """handle_request should compact the body before forwarding to upstream."""
        from unittest.mock import patch

        from agentguard.proxy.compaction.config import CompactionConfig
        from agentguard.proxy.config import ProxyConfig
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

        # Capture what body was forwarded to upstream
        captured_bodies: list[bytes] = []

        async def fake_forward(method, url, headers, body):
            """Fake _forward_request that captures the body."""
            captured_bodies.append(body)

            class FakeResponse:
                status_code = 200
                content = b'{"choices": []}'
                headers: ClassVar[dict[str, str]] = {"content-type": "application/json"}

            return FakeResponse()

        with (
            patch.object(mw, "_forward_request", side_effect=fake_forward),
            patch.object(mw, "_is_streaming_request", return_value=False),
        ):
            from starlette.requests import Request

            scope = {
                "type": "http",
                "method": "POST",
                "path": "/v1/chat/completions",
                "query_string": b"",
                "headers": [(b"content-type", b"application/json")],
            }

            async def receive():
                return {"type": "http.request", "body": original_body}

            req = Request(scope, receive)
            response = await mw.handle_request(req)

        assert response.status_code == 200
        assert len(captured_bodies) == 1

        # The forwarded body should be smaller (compacted content)
        assert len(captured_bodies[0]) < len(original_body)

    @pytest.mark.asyncio
    async def test_handle_request_no_compaction_forwards_original(self):
        """Without compaction, handle_request forwards the original body."""
        from unittest.mock import patch

        from agentguard.proxy.config import ProxyConfig
        from agentguard.proxy.middleware import GuardMiddleware

        config = ProxyConfig(
            upstream_base_url="https://api.example.com",
        )
        mw = GuardMiddleware(config)

        original_body = _make_request_body(turns=5, lines_per_tool=10)

        captured_bodies: list[bytes] = []

        async def fake_forward(method, url, headers, body):
            captured_bodies.append(body)

            class FakeResponse:
                status_code = 200
                content = b'{"choices": []}'
                headers: ClassVar[dict[str, str]] = {"content-type": "application/json"}

            return FakeResponse()

        with (
            patch.object(mw, "_forward_request", side_effect=fake_forward),
            patch.object(mw, "_is_streaming_request", return_value=False),
        ):
            from starlette.requests import Request

            scope = {
                "type": "http",
                "method": "POST",
                "path": "/v1/chat/completions",
                "query_string": b"",
                "headers": [(b"content-type", b"application/json")],
            }

            async def receive():
                return {"type": "http.request", "body": original_body}

            req = Request(scope, receive)
            await mw.handle_request(req)

        assert len(captured_bodies) == 1
        # Without compaction, body should be forwarded unchanged
        assert captured_bodies[0] == original_body

    @pytest.mark.asyncio
    async def test_handle_request_compaction_metrics_in_audit(self):
        """Compaction metrics should be recorded in the audit log."""
        from unittest.mock import patch

        from agentguard.proxy.compaction.config import CompactionConfig
        from agentguard.proxy.config import ProxyConfig
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

        async def fake_forward(method, url, headers, body):
            class FakeResponse:
                status_code = 200
                content = b'{"choices": []}'
                headers: ClassVar[dict[str, str]] = {"content-type": "application/json"}

            return FakeResponse()

        with (
            patch.object(mw, "_forward_request", side_effect=fake_forward),
            patch.object(mw, "_is_streaming_request", return_value=False),
        ):
            from starlette.requests import Request

            scope = {
                "type": "http",
                "method": "POST",
                "path": "/v1/chat/completions",
                "query_string": b"",
                "headers": [(b"content-type", b"application/json")],
            }

            async def receive():
                return {"type": "http.request", "body": original_body}

            req = Request(scope, receive)
            await mw.handle_request(req)

        # Check that compaction metrics are in the audit log
        entries = mw.audit_log.entries
        allowed_entries = [e for e in entries if e.result == "allowed"]
        assert len(allowed_entries) >= 1
        last_allowed = allowed_entries[-1]
        assert last_allowed.metadata is not None
        assert "compaction_phase" in last_allowed.metadata
        assert "compaction_tokens_before" in last_allowed.metadata
        assert "compaction_tokens_after" in last_allowed.metadata

    @pytest.mark.asyncio
    async def test_handle_request_compaction_streaming(self):
        """Compaction should also work for streaming requests."""
        from unittest.mock import patch

        from agentguard.proxy.compaction.config import CompactionConfig
        from agentguard.proxy.config import ProxyConfig
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

        captured_bodies: list[bytes] = []

        async def fake_forward_streaming(method, url, headers, body):
            captured_bodies.append(body)

            async def aiter_bytes():
                yield b"data: {}\n\n"
                yield b"data: [DONE]\n\n"

            class FakeResponse:
                status_code = 200
                headers: ClassVar[dict[str, str]] = {
                    "content-type": "text/event-stream",
                }

                def aiter_bytes(self):
                    return aiter_bytes()

                async def aclose(self):
                    pass

            class FakeClient:
                async def aclose(self):
                    pass

            from agentguard.proxy.middleware import _StreamContext

            return _StreamContext(client=FakeClient(), response=FakeResponse())

        # Mock _is_streaming_request to return True
        # Mock _forward_streaming to capture the body
        with (
            patch.object(
                mw,
                "_forward_streaming",
                side_effect=fake_forward_streaming,
            ),
            patch.object(mw, "_is_streaming_request", return_value=True),
        ):
            from starlette.requests import Request

            scope = {
                "type": "http",
                "method": "POST",
                "path": "/v1/chat/completions",
                "query_string": b"",
                "headers": [(b"content-type", b"application/json")],
            }

            async def receive():
                return {"type": "http.request", "body": original_body}

            req = Request(scope, receive)
            response = await mw.handle_request(req)

        assert response.status_code == 200
        assert len(captured_bodies) == 1

        # The forwarded body should be smaller (compacted content)
        assert len(captured_bodies[0]) < len(original_body)
