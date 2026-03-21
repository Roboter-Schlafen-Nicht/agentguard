"""Tests for Anthropic API format provider adapter.

Covers:
- Provider name and protocol compliance
- Request parameter extraction (system, messages, content, model)
- Structured content blocks (text, tool_use, tool_result)
- Delta scanning (seen_count)
- Response parameter extraction
- Streaming SSE content extraction (content_block_delta, message_stop)
- Edge cases: empty bodies, malformed JSON, missing fields
- Provider registry integration
"""

from __future__ import annotations

import json

import pytest

from agentguard.proxy.providers import Provider


class TestAnthropicProviderProtocol:
    """Verify AnthropicProvider satisfies the Provider protocol."""

    def test_is_provider_instance(self) -> None:
        from agentguard.proxy.providers.anthropic import AnthropicProvider

        provider = AnthropicProvider()
        assert isinstance(provider, Provider)

    def test_name_is_anthropic(self) -> None:
        from agentguard.proxy.providers.anthropic import AnthropicProvider

        provider = AnthropicProvider()
        assert provider.name == "anthropic"


class TestExtractRequestParams:
    """Tests for extract_request_params on Anthropic Messages API format."""

    def _provider(self):
        from agentguard.proxy.providers.anthropic import AnthropicProvider

        return AnthropicProvider()

    def test_simple_user_message(self) -> None:
        body = json.dumps(
            {
                "model": "claude-sonnet-4-20250514",
                "messages": [
                    {"role": "user", "content": "Hello, Claude!"},
                ],
            }
        ).encode()
        params = self._provider().extract_request_params(body)
        assert "messages" in params
        assert "Hello, Claude!" in params["messages"]
        assert "content" in params
        assert "Hello, Claude!" in params["content"]
        assert params["model"] == "claude-sonnet-4-20250514"

    def test_system_prompt_as_string(self) -> None:
        body = json.dumps(
            {
                "model": "claude-sonnet-4-20250514",
                "system": "You are a helpful assistant.",
                "messages": [
                    {"role": "user", "content": "Hi"},
                ],
            }
        ).encode()
        params = self._provider().extract_request_params(body)
        assert params["system"] == "You are a helpful assistant."
        assert "system" not in params.get("content", "")

    def test_system_prompt_as_blocks(self) -> None:
        body = json.dumps(
            {
                "model": "claude-sonnet-4-20250514",
                "system": [
                    {"type": "text", "text": "You are a coding assistant."},
                    {"type": "text", "text": "Be concise."},
                ],
                "messages": [
                    {"role": "user", "content": "Help me"},
                ],
            }
        ).encode()
        params = self._provider().extract_request_params(body)
        assert "You are a coding assistant." in params["system"]
        assert "Be concise." in params["system"]

    def test_structured_content_blocks(self) -> None:
        body = json.dumps(
            {
                "model": "claude-sonnet-4-20250514",
                "messages": [
                    {
                        "role": "user",
                        "content": [
                            {"type": "text", "text": "Analyze this code"},
                            {"type": "text", "text": "def foo(): pass"},
                        ],
                    },
                ],
            }
        ).encode()
        params = self._provider().extract_request_params(body)
        assert "Analyze this code" in params["messages"]
        assert "def foo(): pass" in params["messages"]

    def test_multi_turn_conversation(self) -> None:
        body = json.dumps(
            {
                "model": "claude-sonnet-4-20250514",
                "messages": [
                    {"role": "user", "content": "First message"},
                    {"role": "assistant", "content": "Response"},
                    {"role": "user", "content": "Second message"},
                ],
            }
        ).encode()
        params = self._provider().extract_request_params(body)
        assert "First message" in params["messages"]
        assert "Response" in params["messages"]
        assert "Second message" in params["messages"]

    def test_delta_scanning_with_seen_count(self) -> None:
        body = json.dumps(
            {
                "model": "claude-sonnet-4-20250514",
                "messages": [
                    {"role": "user", "content": "Old message"},
                    {"role": "assistant", "content": "Old response"},
                    {"role": "user", "content": "New message"},
                ],
            }
        ).encode()
        params = self._provider().extract_request_params(body, seen_count=2)
        assert "Old message" not in params.get("messages", "")
        assert "Old response" not in params.get("messages", "")
        assert "New message" in params["messages"]

    def test_seen_count_none_extracts_all(self) -> None:
        body = json.dumps(
            {
                "model": "claude-sonnet-4-20250514",
                "messages": [
                    {"role": "user", "content": "First"},
                    {"role": "user", "content": "Second"},
                ],
            }
        ).encode()
        params = self._provider().extract_request_params(body)
        assert "First" in params["messages"]
        assert "Second" in params["messages"]

    def test_tool_use_and_tool_result_blocks(self) -> None:
        body = json.dumps(
            {
                "model": "claude-sonnet-4-20250514",
                "messages": [
                    {
                        "role": "assistant",
                        "content": [
                            {"type": "text", "text": "Let me check."},
                            {
                                "type": "tool_use",
                                "id": "tool_1",
                                "name": "calculator",
                                "input": {"expr": "2+2"},
                            },
                        ],
                    },
                    {
                        "role": "user",
                        "content": [
                            {
                                "type": "tool_result",
                                "tool_use_id": "tool_1",
                                "content": "4",
                            },
                        ],
                    },
                ],
            }
        ).encode()
        params = self._provider().extract_request_params(body)
        assert "Let me check." in params["messages"]

    def test_empty_messages_array(self) -> None:
        body = json.dumps(
            {
                "model": "claude-sonnet-4-20250514",
                "messages": [],
            }
        ).encode()
        params = self._provider().extract_request_params(body)
        assert "messages" not in params

    def test_invalid_json_raises_value_error(self) -> None:
        with pytest.raises(ValueError, match="Invalid JSON"):
            self._provider().extract_request_params(b"not json")

    def test_non_dict_body_returns_empty(self) -> None:
        body = json.dumps([1, 2, 3]).encode()
        params = self._provider().extract_request_params(body)
        assert params == {}

    def test_no_model_field(self) -> None:
        body = json.dumps(
            {
                "messages": [
                    {"role": "user", "content": "Hi"},
                ],
            }
        ).encode()
        params = self._provider().extract_request_params(body)
        assert "model" not in params

    def test_messages_key_includes_all_content(self) -> None:
        """messages key should contain ALL message content."""
        body = json.dumps(
            {
                "model": "claude-sonnet-4-20250514",
                "system": "Be helpful.",
                "messages": [
                    {"role": "user", "content": "User text"},
                    {"role": "assistant", "content": "Assistant text"},
                ],
            }
        ).encode()
        params = self._provider().extract_request_params(body)
        # messages key should have message content (not system)
        assert "User text" in params["messages"]
        assert "Assistant text" in params["messages"]
        # system should be separate
        assert params["system"] == "Be helpful."


class TestExtractResponseParams:
    """Tests for extract_response_params on Anthropic response format."""

    def _provider(self):
        from agentguard.proxy.providers.anthropic import AnthropicProvider

        return AnthropicProvider()

    def test_simple_text_response(self) -> None:
        body = json.dumps(
            {
                "id": "msg_123",
                "type": "message",
                "role": "assistant",
                "content": [
                    {"type": "text", "text": "Hello! How can I help?"},
                ],
                "stop_reason": "end_turn",
            }
        ).encode()
        params = self._provider().extract_response_params(body)
        assert params["content"] == "Hello! How can I help?"

    def test_multi_block_response(self) -> None:
        body = json.dumps(
            {
                "id": "msg_123",
                "type": "message",
                "role": "assistant",
                "content": [
                    {"type": "text", "text": "Here is the code:"},
                    {"type": "text", "text": "def foo(): pass"},
                ],
            }
        ).encode()
        params = self._provider().extract_response_params(body)
        assert "Here is the code:" in params["content"]
        assert "def foo(): pass" in params["content"]

    def test_tool_use_response(self) -> None:
        body = json.dumps(
            {
                "id": "msg_123",
                "type": "message",
                "role": "assistant",
                "content": [
                    {"type": "text", "text": "Let me look that up."},
                    {
                        "type": "tool_use",
                        "id": "tool_1",
                        "name": "search",
                        "input": {"query": "test"},
                    },
                ],
            }
        ).encode()
        params = self._provider().extract_response_params(body)
        assert "Let me look that up." in params["content"]

    def test_empty_content_array(self) -> None:
        body = json.dumps(
            {
                "id": "msg_123",
                "type": "message",
                "role": "assistant",
                "content": [],
            }
        ).encode()
        params = self._provider().extract_response_params(body)
        assert "content" not in params

    def test_no_content_field(self) -> None:
        body = json.dumps(
            {
                "id": "msg_123",
                "type": "message",
            }
        ).encode()
        params = self._provider().extract_response_params(body)
        assert params == {}

    def test_invalid_json_raises_value_error(self) -> None:
        with pytest.raises(ValueError, match="Invalid JSON"):
            self._provider().extract_response_params(b"bad json")

    def test_non_dict_body_returns_empty(self) -> None:
        body = json.dumps("just a string").encode()
        params = self._provider().extract_response_params(body)
        assert params == {}


class TestExtractStreamContent:
    """Tests for extract_stream_content on Anthropic streaming format."""

    def _provider(self):
        from agentguard.proxy.providers.anthropic import AnthropicProvider

        return AnthropicProvider()

    def test_content_block_delta_text(self) -> None:
        data = json.dumps(
            {
                "type": "content_block_delta",
                "index": 0,
                "delta": {"type": "text_delta", "text": "Hello"},
            }
        )
        parts = self._provider().extract_stream_content(data)
        assert parts == ["Hello"]

    def test_message_start_returns_empty(self) -> None:
        data = json.dumps(
            {
                "type": "message_start",
                "message": {"id": "msg_1", "type": "message"},
            }
        )
        parts = self._provider().extract_stream_content(data)
        assert parts == []

    def test_content_block_start_returns_empty(self) -> None:
        data = json.dumps(
            {
                "type": "content_block_start",
                "index": 0,
                "content_block": {"type": "text", "text": ""},
            }
        )
        parts = self._provider().extract_stream_content(data)
        assert parts == []

    def test_content_block_stop_returns_empty(self) -> None:
        data = json.dumps(
            {
                "type": "content_block_stop",
                "index": 0,
            }
        )
        parts = self._provider().extract_stream_content(data)
        assert parts == []

    def test_message_stop_returns_empty(self) -> None:
        data = json.dumps(
            {
                "type": "message_stop",
            }
        )
        parts = self._provider().extract_stream_content(data)
        assert parts == []

    def test_message_delta_returns_empty(self) -> None:
        data = json.dumps(
            {
                "type": "message_delta",
                "delta": {"stop_reason": "end_turn"},
            }
        )
        parts = self._provider().extract_stream_content(data)
        assert parts == []

    def test_invalid_json_returns_empty(self) -> None:
        parts = self._provider().extract_stream_content("not json")
        assert parts == []

    def test_non_dict_returns_empty(self) -> None:
        parts = self._provider().extract_stream_content(json.dumps([1, 2]))
        assert parts == []

    def test_tool_use_delta_returns_empty(self) -> None:
        data = json.dumps(
            {
                "type": "content_block_delta",
                "index": 1,
                "delta": {
                    "type": "input_json_delta",
                    "partial_json": '{"key":',
                },
            }
        )
        parts = self._provider().extract_stream_content(data)
        assert parts == []


class TestRegistryIntegration:
    """Test that Anthropic provider is registered properly."""

    def test_anthropic_in_provider_list(self) -> None:
        import agentguard.proxy.providers as mod
        from agentguard.proxy.providers import list_providers

        # Reset registry to pick up new provider
        mod._registry = None
        providers = list_providers()
        assert "anthropic" in providers

    def test_get_provider_returns_anthropic(self) -> None:
        import agentguard.proxy.providers as mod
        from agentguard.proxy.providers import get_provider

        mod._registry = None
        provider = get_provider("anthropic")
        assert provider.name == "anthropic"

    def test_detect_provider_by_name(self) -> None:
        import agentguard.proxy.providers as mod
        from agentguard.proxy.providers import detect_provider

        mod._registry = None
        provider = detect_provider(provider_name="anthropic")
        assert provider.name == "anthropic"
