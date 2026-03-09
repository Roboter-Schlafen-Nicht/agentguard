"""Tests for Provider protocol and OpenAI provider adapter."""

from __future__ import annotations

import json

import pytest

from agentguard.proxy.providers import (
    Provider,
    detect_provider,
    get_provider,
    list_providers,
)
from agentguard.proxy.providers.openai import OpenAIProvider


class TestProviderProtocol:
    """Test the Provider protocol contract."""

    def test_openai_implements_protocol(self) -> None:
        provider = OpenAIProvider()
        assert isinstance(provider, Provider)

    def test_provider_has_name(self) -> None:
        provider = OpenAIProvider()
        assert provider.name == "openai"


class TestProviderRegistry:
    """Test provider registry functions."""

    def test_list_providers_includes_openai(self) -> None:
        names = list_providers()
        assert "openai" in names

    def test_get_provider_returns_openai(self) -> None:
        provider = get_provider("openai")
        assert isinstance(provider, OpenAIProvider)

    def test_get_provider_unknown_raises(self) -> None:
        with pytest.raises(ValueError, match="not-a-provider"):
            get_provider("not-a-provider")

    def test_detect_provider_default_is_openai(self) -> None:
        provider = detect_provider()
        assert provider.name == "openai"

    def test_detect_provider_by_name(self) -> None:
        provider = detect_provider(provider_name="openai")
        assert provider.name == "openai"


class TestOpenAIProviderRequestParsing:
    """Test OpenAI provider request content extraction."""

    def test_simple_user_message(self) -> None:
        body = json.dumps(
            {
                "model": "gpt-4",
                "messages": [
                    {"role": "user", "content": "Hello!"},
                ],
            }
        ).encode()
        provider = OpenAIProvider()
        params = provider.extract_request_params(body)
        assert params["messages"] == "Hello!"
        assert params["content"] == "Hello!"
        assert params["model"] == "gpt-4"
        assert "system" not in params

    def test_system_and_user_messages(self) -> None:
        body = json.dumps(
            {
                "model": "gpt-4",
                "messages": [
                    {"role": "system", "content": "You are helpful."},
                    {"role": "user", "content": "Hi there"},
                ],
            }
        ).encode()
        provider = OpenAIProvider()
        params = provider.extract_request_params(body)
        assert "You are helpful." in params["messages"]
        assert "Hi there" in params["messages"]
        assert params["system"] == "You are helpful."
        assert params["content"] == "Hi there"

    def test_multi_turn_conversation(self) -> None:
        body = json.dumps(
            {
                "model": "gpt-4",
                "messages": [
                    {"role": "user", "content": "Question 1"},
                    {"role": "assistant", "content": "Answer 1"},
                    {"role": "user", "content": "Question 2"},
                ],
            }
        ).encode()
        provider = OpenAIProvider()
        params = provider.extract_request_params(body)
        assert "Question 1" in params["messages"]
        assert "Answer 1" in params["messages"]
        assert "Question 2" in params["messages"]

    def test_structured_content_blocks(self) -> None:
        body = json.dumps(
            {
                "model": "gpt-4o",
                "messages": [
                    {
                        "role": "user",
                        "content": [
                            {"type": "text", "text": "Describe this image"},
                            {
                                "type": "image_url",
                                "image_url": {"url": "https://example.com/img.png"},
                            },
                        ],
                    },
                ],
            }
        ).encode()
        provider = OpenAIProvider()
        params = provider.extract_request_params(body)
        assert params["messages"] == "Describe this image"

    def test_invalid_json_raises(self) -> None:
        provider = OpenAIProvider()
        with pytest.raises(ValueError, match="Invalid JSON"):
            provider.extract_request_params(b"not json")

    def test_empty_messages_array(self) -> None:
        body = json.dumps({"model": "gpt-4", "messages": []}).encode()
        provider = OpenAIProvider()
        params = provider.extract_request_params(body)
        assert "messages" not in params

    def test_no_messages_field(self) -> None:
        body = json.dumps({"model": "gpt-4"}).encode()
        provider = OpenAIProvider()
        params = provider.extract_request_params(body)
        assert "messages" not in params
        assert params["model"] == "gpt-4"


class TestOpenAIProviderResponseParsing:
    """Test OpenAI provider response content extraction."""

    def test_standard_chat_completion(self) -> None:
        body = json.dumps(
            {
                "choices": [
                    {
                        "message": {
                            "role": "assistant",
                            "content": "Hello! How can I help?",
                        },
                        "finish_reason": "stop",
                    }
                ]
            }
        ).encode()
        provider = OpenAIProvider()
        params = provider.extract_response_params(body)
        assert params["content"] == "Hello! How can I help?"

    def test_multiple_choices(self) -> None:
        body = json.dumps(
            {
                "choices": [
                    {"message": {"content": "Response A"}},
                    {"message": {"content": "Response B"}},
                ]
            }
        ).encode()
        provider = OpenAIProvider()
        params = provider.extract_response_params(body)
        assert "Response A" in params["content"]
        assert "Response B" in params["content"]

    def test_streaming_delta(self) -> None:
        body = json.dumps(
            {"choices": [{"delta": {"content": "Hello"}, "index": 0}]}
        ).encode()
        provider = OpenAIProvider()
        params = provider.extract_response_params(body)
        assert params["content"] == "Hello"

    def test_invalid_json_raises(self) -> None:
        provider = OpenAIProvider()
        with pytest.raises(ValueError, match="Invalid JSON"):
            provider.extract_response_params(b"not json {")

    def test_empty_choices(self) -> None:
        body = json.dumps({"choices": []}).encode()
        provider = OpenAIProvider()
        params = provider.extract_response_params(body)
        assert "content" not in params

    def test_no_content_in_message(self) -> None:
        body = json.dumps({"choices": [{"message": {"role": "assistant"}}]}).encode()
        provider = OpenAIProvider()
        params = provider.extract_response_params(body)
        assert "content" not in params


class TestOpenAIProviderStreamContent:
    """Test OpenAI provider streaming content extraction."""

    def test_extract_delta_content(self) -> None:
        data_str = json.dumps(
            {"choices": [{"delta": {"content": "Hello"}, "index": 0}]}
        )
        provider = OpenAIProvider()
        parts = provider.extract_stream_content(data_str)
        assert parts == ["Hello"]

    def test_done_marker_returns_empty(self) -> None:
        provider = OpenAIProvider()
        parts = provider.extract_stream_content("[DONE]")
        assert parts == []

    def test_empty_delta(self) -> None:
        data_str = json.dumps({"choices": [{"delta": {}, "index": 0}]})
        provider = OpenAIProvider()
        parts = provider.extract_stream_content(data_str)
        assert parts == []

    def test_multiple_choices_stream(self) -> None:
        data_str = json.dumps(
            {
                "choices": [
                    {"delta": {"content": "A"}, "index": 0},
                    {"delta": {"content": "B"}, "index": 1},
                ]
            }
        )
        provider = OpenAIProvider()
        parts = provider.extract_stream_content(data_str)
        assert parts == ["A", "B"]

    def test_role_only_delta(self) -> None:
        """First chunk often has role but no content."""
        data_str = json.dumps(
            {"choices": [{"delta": {"role": "assistant"}, "index": 0}]}
        )
        provider = OpenAIProvider()
        parts = provider.extract_stream_content(data_str)
        assert parts == []

    def test_invalid_json_returns_empty(self) -> None:
        provider = OpenAIProvider()
        parts = provider.extract_stream_content("not json")
        assert parts == []

    def test_non_dict_returns_empty(self) -> None:
        provider = OpenAIProvider()
        parts = provider.extract_stream_content('"just a string"')
        assert parts == []
