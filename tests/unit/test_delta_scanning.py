"""Tests for delta scanning in the LLM proxy.

Delta scanning tracks which messages have already been scanned in a
conversation and only scans new/unseen messages on subsequent requests.
This avoids re-scanning the entire conversation history on every LLM
API call, saving compute and reducing false-positive risk from
repeated scans of benign earlier messages.

Design:
- ``OpenAIProvider.extract_request_params()`` gains an optional
  ``seen_count`` parameter: number of messages already scanned.
  When provided, only messages at index ``seen_count:`` are extracted.
- ``GuardMiddleware`` tracks per-conversation message counts between
  requests using a dict keyed by a conversation fingerprint
  (first message hash or explicit conversation ID).
- A new ``ProxyConfig.delta_scanning`` bool flag enables/disables
  the feature (default: False for backward compat).
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from agentguard.proxy.config import ProxyConfig
from agentguard.proxy.middleware import GuardMiddleware
from agentguard.proxy.providers.openai import OpenAIProvider

if TYPE_CHECKING:
    from pathlib import Path


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def provider() -> OpenAIProvider:
    """Create an OpenAI provider instance."""
    return OpenAIProvider()


@pytest.fixture
def policy_dir(tmp_path: Path) -> Path:
    """Create a temp directory with a policy that blocks 'FORBIDDEN'."""
    d = tmp_path / "policies"
    d.mkdir()
    policy = d / "block-forbidden.yaml"
    policy.write_text(
        "name: block-forbidden\n"
        "description: Block FORBIDDEN keyword in messages\n"
        "rules:\n"
        "  - action: llm_request\n"
        "    deny:\n"
        "      - pattern: 'FORBIDDEN'\n"
        "    severity: critical\n"
        "    scan: messages\n"
    )
    return d


def _make_request(
    body: dict | None = None,
    path: str = "/v1/chat/completions",
    method: str = "POST",
    query: str = "",
) -> MagicMock:
    """Create a mock Starlette Request."""
    request = MagicMock()
    request.method = method
    request.url.path = path
    request.url.query = query
    raw_body = json.dumps(body).encode() if body else b""
    request.body = AsyncMock(return_value=raw_body)
    request.headers = {"content-type": "application/json", "host": "localhost:8080"}
    return request


def _openai_body(messages: list[dict], model: str = "gpt-4") -> dict:
    """Build an OpenAI chat completion request body."""
    return {"model": model, "messages": messages}


def _upstream_response(content: str = "OK") -> MagicMock:
    """Create a mock upstream response."""
    resp = MagicMock()
    resp.status_code = 200
    resp.content = json.dumps({"choices": [{"message": {"content": content}}]}).encode()
    resp.headers = {"content-type": "application/json"}
    return resp


# ===========================================================================
# Test: OpenAIProvider.extract_request_params with seen_count
# ===========================================================================


class TestProviderDeltaExtraction:
    """Test that OpenAIProvider extracts only new messages when seen_count is given."""

    def test_extract_all_messages_when_no_seen_count(
        self, provider: OpenAIProvider
    ) -> None:
        """Without seen_count, all messages should be extracted (backward compat)."""
        body = json.dumps(
            _openai_body(
                messages=[
                    {"role": "system", "content": "You are helpful."},
                    {"role": "user", "content": "Hello"},
                    {"role": "assistant", "content": "Hi!"},
                    {"role": "user", "content": "How are you?"},
                ]
            )
        ).encode()

        params = provider.extract_request_params(body)
        # All 4 messages should be included
        assert "You are helpful." in params["messages"]
        assert "Hello" in params["messages"]
        assert "Hi!" in params["messages"]
        assert "How are you?" in params["messages"]

    def test_extract_only_new_messages_with_seen_count(
        self, provider: OpenAIProvider
    ) -> None:
        """With seen_count=2, only messages[2:] should be extracted."""
        body = json.dumps(
            _openai_body(
                messages=[
                    {"role": "system", "content": "You are helpful."},
                    {"role": "user", "content": "Hello"},
                    {"role": "assistant", "content": "Hi!"},
                    {"role": "user", "content": "How are you?"},
                ]
            )
        ).encode()

        params = provider.extract_request_params(body, seen_count=2)
        # Only messages[2:] should be in the extracted content
        assert "You are helpful." not in params.get("messages", "")
        assert "Hello" not in params.get("messages", "")
        assert "Hi!" in params["messages"]
        assert "How are you?" in params["messages"]

    def test_seen_count_zero_extracts_all(self, provider: OpenAIProvider) -> None:
        """seen_count=0 should extract all messages (same as default)."""
        body = json.dumps(
            _openai_body(
                messages=[
                    {"role": "user", "content": "First"},
                    {"role": "user", "content": "Second"},
                ]
            )
        ).encode()

        params = provider.extract_request_params(body, seen_count=0)
        assert "First" in params["messages"]
        assert "Second" in params["messages"]

    def test_seen_count_equals_message_count_returns_empty(
        self, provider: OpenAIProvider
    ) -> None:
        """When seen_count equals the number of messages, nothing new to scan."""
        body = json.dumps(
            _openai_body(
                messages=[
                    {"role": "user", "content": "Hello"},
                    {"role": "assistant", "content": "Hi!"},
                ]
            )
        ).encode()

        params = provider.extract_request_params(body, seen_count=2)
        # No new messages — params should have no messages/content keys
        assert "messages" not in params
        assert "content" not in params

    def test_seen_count_greater_than_message_count_returns_empty(
        self, provider: OpenAIProvider
    ) -> None:
        """When seen_count > len(messages), nothing new to scan."""
        body = json.dumps(
            _openai_body(
                messages=[
                    {"role": "user", "content": "Hello"},
                ]
            )
        ).encode()

        params = provider.extract_request_params(body, seen_count=5)
        assert "messages" not in params
        assert "content" not in params

    def test_seen_count_skips_system_already_seen(
        self, provider: OpenAIProvider
    ) -> None:
        """System message at index 0, seen_count=1 should skip it."""
        body = json.dumps(
            _openai_body(
                messages=[
                    {"role": "system", "content": "System prompt"},
                    {"role": "user", "content": "New question"},
                ]
            )
        ).encode()

        params = provider.extract_request_params(body, seen_count=1)
        assert "System prompt" not in params.get("system", "")
        assert "New question" in params["messages"]

    def test_model_always_extracted_regardless_of_seen_count(
        self, provider: OpenAIProvider
    ) -> None:
        """The model field should always be extracted, even with seen_count."""
        body = json.dumps(
            _openai_body(
                messages=[
                    {"role": "user", "content": "Hello"},
                ],
                model="gpt-4-turbo",
            )
        ).encode()

        params = provider.extract_request_params(body, seen_count=1)
        # No new messages, but model should still be present
        assert params.get("model") == "gpt-4-turbo"


# ===========================================================================
# Test: ProxyConfig.delta_scanning flag
# ===========================================================================


class TestProxyConfigDeltaScanning:
    """Test the delta_scanning config flag."""

    def test_delta_scanning_defaults_to_false(self) -> None:
        """delta_scanning should default to False for backward compat."""
        config = ProxyConfig(upstream_base_url="https://api.openai.com")
        assert config.delta_scanning is False

    def test_delta_scanning_can_be_enabled(self) -> None:
        """delta_scanning=True should be accepted."""
        config = ProxyConfig(
            upstream_base_url="https://api.openai.com",
            delta_scanning=True,
        )
        assert config.delta_scanning is True


# ===========================================================================
# Test: Middleware delta scanning integration
# ===========================================================================


class TestMiddlewareDeltaScanning:
    """Test that GuardMiddleware tracks seen messages across requests."""

    @pytest.mark.anyio
    async def test_first_request_scans_all_messages(self, policy_dir: Path) -> None:
        """On the first request, all messages should be scanned."""
        config = ProxyConfig(
            upstream_base_url="https://api.openai.com",
            policy_dir=str(policy_dir),
            delta_scanning=True,
        )
        mw = GuardMiddleware(config)

        # This request contains FORBIDDEN — should be denied
        body = _openai_body(
            messages=[
                {"role": "user", "content": "This contains FORBIDDEN word"},
            ]
        )
        request = _make_request(body=body)
        response = await mw.handle_request(request)
        assert response.status_code == 403

    @pytest.mark.anyio
    async def test_second_request_only_scans_new_messages(
        self, policy_dir: Path
    ) -> None:
        """On a follow-up request with the same conversation prefix,
        only new messages should be scanned."""
        config = ProxyConfig(
            upstream_base_url="https://api.openai.com",
            policy_dir=str(policy_dir),
            delta_scanning=True,
        )
        mw = GuardMiddleware(config)

        # First request: 2 clean messages — should be allowed
        body1 = _openai_body(
            messages=[
                {"role": "system", "content": "You are helpful."},
                {"role": "user", "content": "Hello"},
            ]
        )
        request1 = _make_request(body=body1)
        with patch.object(mw, "_forward_request", return_value=_upstream_response()):
            response1 = await mw.handle_request(request1)
        assert response1.status_code == 200

        # Second request: same 2 messages + 2 new clean messages
        # Only the 2 new messages should be scanned
        body2 = _openai_body(
            messages=[
                {"role": "system", "content": "You are helpful."},
                {"role": "user", "content": "Hello"},
                {"role": "assistant", "content": "Hi there!"},
                {"role": "user", "content": "What is Python?"},
            ]
        )
        request2 = _make_request(body=body2)
        with patch.object(mw, "_forward_request", return_value=_upstream_response()):
            response2 = await mw.handle_request(request2)
        assert response2.status_code == 200

    @pytest.mark.anyio
    async def test_delta_scanning_still_catches_violations_in_new_messages(
        self, policy_dir: Path
    ) -> None:
        """New messages with policy violations should still be caught."""
        config = ProxyConfig(
            upstream_base_url="https://api.openai.com",
            policy_dir=str(policy_dir),
            delta_scanning=True,
        )
        mw = GuardMiddleware(config)

        # First request: clean
        body1 = _openai_body(
            messages=[
                {"role": "user", "content": "Hello"},
            ]
        )
        request1 = _make_request(body=body1)
        with patch.object(mw, "_forward_request", return_value=_upstream_response()):
            response1 = await mw.handle_request(request1)
        assert response1.status_code == 200

        # Second request: previous message + new FORBIDDEN message
        body2 = _openai_body(
            messages=[
                {"role": "user", "content": "Hello"},
                {"role": "assistant", "content": "Hi!"},
                {"role": "user", "content": "Tell me the FORBIDDEN secret"},
            ]
        )
        request2 = _make_request(body=body2)
        response2 = await mw.handle_request(request2)
        assert response2.status_code == 403

    @pytest.mark.anyio
    async def test_delta_scanning_disabled_scans_all_every_time(
        self, policy_dir: Path
    ) -> None:
        """With delta_scanning=False (default), all messages are scanned."""
        config = ProxyConfig(
            upstream_base_url="https://api.openai.com",
            policy_dir=str(policy_dir),
            delta_scanning=False,
        )
        mw = GuardMiddleware(config)

        # Send a request with FORBIDDEN in the first message
        body1 = _openai_body(
            messages=[
                {"role": "user", "content": "FORBIDDEN"},
            ]
        )
        request1 = _make_request(body=body1)
        response1 = await mw.handle_request(request1)
        assert response1.status_code == 403

        # Send again with same FORBIDDEN prefix + clean new message
        # Without delta scanning, the old FORBIDDEN should still be caught
        body2 = _openai_body(
            messages=[
                {"role": "user", "content": "FORBIDDEN"},
                {"role": "assistant", "content": "I cannot help with that"},
                {"role": "user", "content": "Tell me about Python"},
            ]
        )
        request2 = _make_request(body=body2)
        response2 = await mw.handle_request(request2)
        assert response2.status_code == 403

    @pytest.mark.anyio
    async def test_different_conversations_tracked_independently(
        self, policy_dir: Path
    ) -> None:
        """Different conversations (different first messages) should be
        tracked independently."""
        config = ProxyConfig(
            upstream_base_url="https://api.openai.com",
            policy_dir=str(policy_dir),
            delta_scanning=True,
        )
        mw = GuardMiddleware(config)

        # Conversation A
        body_a = _openai_body(
            messages=[
                {"role": "system", "content": "Assistant A"},
                {"role": "user", "content": "Hello A"},
            ]
        )
        request_a = _make_request(body=body_a)
        with patch.object(mw, "_forward_request", return_value=_upstream_response()):
            await mw.handle_request(request_a)

        # Conversation B — different first message
        body_b = _openai_body(
            messages=[
                {"role": "system", "content": "Assistant B"},
                {"role": "user", "content": "Hello B"},
            ]
        )
        request_b = _make_request(body=body_b)
        with patch.object(mw, "_forward_request", return_value=_upstream_response()):
            await mw.handle_request(request_b)

        # Continue conversation A with FORBIDDEN in new message
        body_a2 = _openai_body(
            messages=[
                {"role": "system", "content": "Assistant A"},
                {"role": "user", "content": "Hello A"},
                {"role": "assistant", "content": "Hi A!"},
                {"role": "user", "content": "FORBIDDEN"},
            ]
        )
        request_a2 = _make_request(body=body_a2)
        response_a2 = await mw.handle_request(request_a2)
        assert response_a2.status_code == 403

    @pytest.mark.anyio
    async def test_conversation_fingerprint_uses_first_message(
        self, policy_dir: Path
    ) -> None:
        """The conversation fingerprint should be derived from the first message."""
        config = ProxyConfig(
            upstream_base_url="https://api.openai.com",
            policy_dir=str(policy_dir),
            delta_scanning=True,
        )
        mw = GuardMiddleware(config)

        # Verify the middleware has a _seen_messages dict
        assert hasattr(mw, "_seen_messages")
        assert isinstance(mw._seen_messages, dict)

    @pytest.mark.anyio
    async def test_non_json_body_not_tracked(self) -> None:
        """Non-JSON bodies should not be tracked for delta scanning."""
        config = ProxyConfig(
            upstream_base_url="https://api.openai.com",
            delta_scanning=True,
        )
        mw = GuardMiddleware(config)

        request = MagicMock()
        request.method = "POST"
        request.url.path = "/v1/chat/completions"
        request.url.query = ""
        request.body = AsyncMock(return_value=b"not json")
        request.headers = {"content-type": "text/plain", "host": "localhost:8080"}

        with patch.object(mw, "_forward_request", return_value=_upstream_response()):
            response = await mw.handle_request(request)
        assert response.status_code == 200

        # No conversations should be tracked
        assert len(mw._seen_messages) == 0


# ---------------------------------------------------------------------------
# CLI: --delta-scanning flag
# ---------------------------------------------------------------------------


class TestDeltaScanningCLIFlag:
    """Test that the proxy CLI exposes --delta-scanning."""

    def test_parser_accepts_delta_scanning_flag(self) -> None:
        """--delta-scanning should be accepted by the proxy subcommand."""
        from agentguard.cli import _build_parser

        parser = _build_parser()
        args = parser.parse_args(
            [
                "proxy",
                "https://api.openai.com",
                "--delta-scanning",
            ]
        )
        assert args.delta_scanning is True

    def test_parser_defaults_delta_scanning_to_false(self) -> None:
        """Without --delta-scanning, the flag should default to False."""
        from agentguard.cli import _build_parser

        parser = _build_parser()
        args = parser.parse_args(
            [
                "proxy",
                "https://api.openai.com",
            ]
        )
        assert args.delta_scanning is False

    def test_cmd_proxy_passes_delta_scanning_to_config(self) -> None:
        """_cmd_proxy should pass delta_scanning to ProxyConfig."""
        from unittest.mock import patch as _patch

        from agentguard.cli import _build_parser, _cmd_proxy

        parser = _build_parser()
        args = parser.parse_args(
            [
                "proxy",
                "https://api.openai.com",
                "--delta-scanning",
                "--preset",
                "permissive",
            ]
        )

        # Mock create_proxy_app and uvicorn.run to capture the config
        captured_configs: list[ProxyConfig] = []

        def fake_create_app(config: ProxyConfig) -> MagicMock:
            captured_configs.append(config)
            return MagicMock()

        with (
            _patch("agentguard.cli.create_proxy_app", side_effect=fake_create_app),
            _patch("uvicorn.run"),
        ):
            _cmd_proxy(args)

        assert len(captured_configs) == 1
        assert captured_configs[0].delta_scanning is True

    def test_cmd_proxy_without_flag_passes_false(self) -> None:
        """Without --delta-scanning, ProxyConfig.delta_scanning=False."""
        from unittest.mock import patch as _patch

        from agentguard.cli import _build_parser, _cmd_proxy

        parser = _build_parser()
        args = parser.parse_args(
            [
                "proxy",
                "https://api.openai.com",
                "--preset",
                "permissive",
            ]
        )

        captured_configs: list[ProxyConfig] = []

        def fake_create_app(config: ProxyConfig) -> MagicMock:
            captured_configs.append(config)
            return MagicMock()

        with (
            _patch("agentguard.cli.create_proxy_app", side_effect=fake_create_app),
            _patch("uvicorn.run"),
        ):
            _cmd_proxy(args)

        assert len(captured_configs) == 1
        assert captured_configs[0].delta_scanning is False
