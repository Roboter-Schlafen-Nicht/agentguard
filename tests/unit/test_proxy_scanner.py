"""Tests for the LLM request/response scanner."""

from __future__ import annotations

import json

import pytest

from agentguard.proxy.scanner import (
    extract_request_params,
    extract_response_params,
)

# ===========================================================================
# Request scanning: OpenAI format
# ===========================================================================


class TestExtractRequestParamsOpenAI:
    """Test scanning OpenAI-format chat completion requests."""

    def test_simple_user_message(self) -> None:
        """Extract content from a single user message."""
        body = json.dumps(
            {
                "model": "gpt-4",
                "messages": [
                    {"role": "user", "content": "Hello, world!"},
                ],
            }
        ).encode()

        params = extract_request_params(body)
        assert params["messages"] == "Hello, world!"
        assert params["content"] == "Hello, world!"
        assert params["model"] == "gpt-4"
        assert "system" not in params

    def test_system_and_user_messages(self) -> None:
        """Extract system prompt and user message separately."""
        body = json.dumps(
            {
                "model": "gpt-4",
                "messages": [
                    {"role": "system", "content": "You are a helpful assistant."},
                    {"role": "user", "content": "What is Python?"},
                ],
            }
        ).encode()

        params = extract_request_params(body)
        assert "You are a helpful assistant." in params["messages"]
        assert "What is Python?" in params["messages"]
        assert params["system"] == "You are a helpful assistant."
        assert params["content"] == "What is Python?"

    def test_multi_turn_conversation(self) -> None:
        """Extract content from a multi-turn conversation."""
        body = json.dumps(
            {
                "model": "gpt-4",
                "messages": [
                    {"role": "system", "content": "Be concise."},
                    {"role": "user", "content": "Hi"},
                    {"role": "assistant", "content": "Hello!"},
                    {"role": "user", "content": "How are you?"},
                ],
            }
        ).encode()

        params = extract_request_params(body)
        assert "Be concise." in params["system"]
        assert "Hi" in params["content"]
        assert "Hello!" in params["content"]
        assert "How are you?" in params["content"]
        # All content combined in messages
        assert "Be concise." in params["messages"]
        assert "Hi" in params["messages"]

    def test_structured_content_blocks(self) -> None:
        """Handle structured content (list of text blocks)."""
        body = json.dumps(
            {
                "model": "gpt-4-vision",
                "messages": [
                    {
                        "role": "user",
                        "content": [
                            {"type": "text", "text": "Describe this image."},
                            {
                                "type": "image_url",
                                "image_url": {"url": "https://example.com/img.png"},
                            },
                        ],
                    },
                ],
            }
        ).encode()

        params = extract_request_params(body)
        assert "Describe this image." in params["messages"]
        assert "Describe this image." in params["content"]

    def test_empty_messages_list(self) -> None:
        """Empty messages list should produce no message params."""
        body = json.dumps(
            {
                "model": "gpt-4",
                "messages": [],
            }
        ).encode()

        params = extract_request_params(body)
        assert "messages" not in params
        assert "content" not in params
        assert params["model"] == "gpt-4"

    def test_no_messages_key(self) -> None:
        """Request without messages key should only extract model."""
        body = json.dumps(
            {
                "model": "text-embedding-ada-002",
                "input": "Some text to embed",
            }
        ).encode()

        params = extract_request_params(body)
        assert params.get("model") == "text-embedding-ada-002"
        assert "messages" not in params


# ===========================================================================
# Request scanning: Anthropic format
# ===========================================================================


class TestExtractRequestParamsAnthropic:
    """Test scanning Anthropic-format requests."""

    def test_anthropic_system_field(self) -> None:
        """Extract Anthropic top-level system field."""
        body = json.dumps(
            {
                "model": "claude-3-opus",
                "system": "You are Claude.",
                "messages": [
                    {"role": "user", "content": "Hello"},
                ],
            }
        ).encode()

        params = extract_request_params(body)
        assert "You are Claude." in params["system"]
        assert params["model"] == "claude-3-opus"
        assert "Hello" in params["content"]

    def test_anthropic_system_combined_with_openai_system(self) -> None:
        """Both top-level system and messages system should be combined."""
        body = json.dumps(
            {
                "system": "Top-level system prompt.",
                "messages": [
                    {"role": "system", "content": "Messages system prompt."},
                    {"role": "user", "content": "Hi"},
                ],
            }
        ).encode()

        params = extract_request_params(body)
        assert "Messages system prompt." in params["system"]
        assert "Top-level system prompt." in params["system"]


# ===========================================================================
# Request scanning: Edge cases
# ===========================================================================


class TestExtractRequestParamsEdgeCases:
    """Test edge cases in request scanning."""

    def test_invalid_json_raises(self) -> None:
        """Non-JSON body should raise ValueError."""
        with pytest.raises(ValueError, match="Invalid JSON"):
            extract_request_params(b"not json")

    def test_non_dict_body(self) -> None:
        """JSON array body should return empty params."""
        body = json.dumps([1, 2, 3]).encode()
        params = extract_request_params(body)
        assert params == {}

    def test_empty_body(self) -> None:
        """Empty body should raise ValueError."""
        with pytest.raises(ValueError):
            extract_request_params(b"")

    def test_messages_with_non_dict_entries(self) -> None:
        """Non-dict entries in messages should be skipped."""
        body = json.dumps(
            {
                "messages": [
                    "not a dict",
                    42,
                    {"role": "user", "content": "Valid"},
                ],
            }
        ).encode()

        params = extract_request_params(body)
        assert params["content"] == "Valid"

    def test_message_with_none_content(self) -> None:
        """Message with null content should be skipped."""
        body = json.dumps(
            {
                "messages": [
                    {"role": "user", "content": None},
                    {"role": "user", "content": "After null"},
                ],
            }
        ).encode()

        params = extract_request_params(body)
        assert params["content"] == "After null"

    def test_message_with_empty_string_content(self) -> None:
        """Message with empty string content should be skipped."""
        body = json.dumps(
            {
                "messages": [
                    {"role": "user", "content": ""},
                    {"role": "user", "content": "After empty"},
                ],
            }
        ).encode()

        params = extract_request_params(body)
        assert params["content"] == "After empty"


# ===========================================================================
# Response scanning: OpenAI format
# ===========================================================================


class TestExtractResponseParamsOpenAI:
    """Test scanning OpenAI-format responses."""

    def test_simple_completion(self) -> None:
        """Extract content from a standard chat completion response."""
        body = json.dumps(
            {
                "id": "chatcmpl-abc",
                "choices": [
                    {
                        "index": 0,
                        "message": {
                            "role": "assistant",
                            "content": "Python is a programming language.",
                        },
                        "finish_reason": "stop",
                    },
                ],
            }
        ).encode()

        params = extract_response_params(body)
        assert params["content"] == "Python is a programming language."

    def test_multiple_choices(self) -> None:
        """Extract content from multiple choices."""
        body = json.dumps(
            {
                "choices": [
                    {"message": {"content": "Answer A"}},
                    {"message": {"content": "Answer B"}},
                ],
            }
        ).encode()

        params = extract_response_params(body)
        assert "Answer A" in params["content"]
        assert "Answer B" in params["content"]

    def test_streaming_delta(self) -> None:
        """Extract content from a streaming chunk with delta."""
        body = json.dumps(
            {
                "choices": [
                    {
                        "delta": {"content": "Hello"},
                    },
                ],
            }
        ).encode()

        params = extract_response_params(body)
        assert params["content"] == "Hello"

    def test_empty_choices(self) -> None:
        """Empty choices should produce no content."""
        body = json.dumps({"choices": []}).encode()
        params = extract_response_params(body)
        assert "content" not in params


# ===========================================================================
# Response scanning: Anthropic format
# ===========================================================================


class TestExtractResponseParamsAnthropic:
    """Test scanning Anthropic-format responses."""

    def test_anthropic_content_blocks(self) -> None:
        """Extract text from Anthropic content blocks."""
        body = json.dumps(
            {
                "content": [
                    {"type": "text", "text": "Here is my response."},
                ],
                "stop_reason": "end_turn",
            }
        ).encode()

        params = extract_response_params(body)
        assert params["content"] == "Here is my response."

    def test_anthropic_multiple_blocks(self) -> None:
        """Extract text from multiple Anthropic content blocks."""
        body = json.dumps(
            {
                "content": [
                    {"type": "text", "text": "First part."},
                    {"type": "text", "text": "Second part."},
                ],
            }
        ).encode()

        params = extract_response_params(body)
        assert "First part." in params["content"]
        assert "Second part." in params["content"]

    def test_anthropic_non_text_blocks_skipped(self) -> None:
        """Non-text blocks should be skipped."""
        body = json.dumps(
            {
                "content": [
                    {"type": "tool_use", "id": "abc", "name": "search"},
                    {"type": "text", "text": "Results found."},
                ],
            }
        ).encode()

        params = extract_response_params(body)
        assert params["content"] == "Results found."


# ===========================================================================
# Response scanning: Edge cases
# ===========================================================================


class TestExtractResponseParamsEdgeCases:
    """Test edge cases in response scanning."""

    def test_invalid_json_raises(self) -> None:
        """Non-JSON body should raise ValueError."""
        with pytest.raises(ValueError, match="Invalid JSON"):
            extract_response_params(b"not json")

    def test_non_dict_body(self) -> None:
        """JSON array body should return empty params."""
        body = json.dumps([1, 2, 3]).encode()
        params = extract_response_params(body)
        assert params == {}

    def test_no_content_fields(self) -> None:
        """Response with no recognizable content should return empty."""
        body = json.dumps({"id": "abc", "object": "chat.completion"}).encode()
        params = extract_response_params(body)
        assert params == {}


# ===========================================================================
# Scanner delegation to provider
# ===========================================================================


class TestScannerProviderDelegation:
    """Test that scanner functions can delegate to a provider."""

    def test_request_params_match_openai_provider(self) -> None:
        """Scanner request params match OpenAI provider."""
        from agentguard.proxy.providers.openai import OpenAIProvider

        body = json.dumps(
            {
                "model": "gpt-4",
                "messages": [
                    {"role": "system", "content": "Be helpful."},
                    {"role": "user", "content": "Hello!"},
                ],
            }
        ).encode()

        scanner_params = extract_request_params(body)
        provider_params = OpenAIProvider().extract_request_params(body)

        # Both should extract the same key params for OpenAI format
        assert scanner_params["messages"] == provider_params["messages"]
        assert scanner_params["system"] == provider_params["system"]
        assert scanner_params["content"] == provider_params["content"]
        assert scanner_params["model"] == provider_params["model"]

    def test_response_params_match_openai_provider(self) -> None:
        """Scanner response params match OpenAI provider."""
        from agentguard.proxy.providers.openai import OpenAIProvider

        body = json.dumps(
            {"choices": [{"message": {"content": "Hello there!"}}]}
        ).encode()

        scanner_params = extract_response_params(body)
        provider_params = OpenAIProvider().extract_response_params(body)

        assert scanner_params["content"] == provider_params["content"]
