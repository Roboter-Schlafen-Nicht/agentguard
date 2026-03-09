"""OpenAI-compatible API format adapter.

Handles parsing and extraction for the OpenAI ``/v1/chat/completions``
format, which is also used by Azure OpenAI, GitHub Copilot, LiteLLM,
vLLM, Ollama, and many other OpenAI-compatible providers.
"""

from __future__ import annotations

import json
from typing import Any


class OpenAIProvider:
    """Provider adapter for OpenAI-compatible LLM APIs.

    Parses request bodies (messages array with role/content),
    response bodies (choices array with message/content), and
    streaming SSE deltas (choices[].delta.content).
    """

    @property
    def name(self) -> str:
        """Provider identifier."""
        return "openai"

    def extract_request_params(self, body: bytes) -> dict[str, str]:
        """Extract scannable parameters from an OpenAI request body.

        Parses the JSON body and extracts:
        - ``messages``: Concatenated content from all messages.
        - ``system``: System prompt if present (role=system messages).
        - ``content``: All user/assistant message content concatenated.
        - ``model``: Model name if present.

        Args:
            body: Raw request body bytes.

        Returns:
            Dictionary of parameter keys to string values.

        Raises:
            ValueError: If the body is not valid JSON.
        """
        data = self._parse_json(body, "request")

        if not isinstance(data, dict):
            return {}

        params: dict[str, str] = {}

        messages = data.get("messages")
        if isinstance(messages, list):
            all_content: list[str] = []
            system_parts: list[str] = []
            user_assistant_parts: list[str] = []

            for msg in messages:
                if not isinstance(msg, dict):
                    continue
                role = msg.get("role", "")
                content = self._extract_content(msg.get("content"))
                if not content:
                    continue

                all_content.append(content)

                if role == "system":
                    system_parts.append(content)
                else:
                    user_assistant_parts.append(content)

            if all_content:
                params["messages"] = "\n".join(all_content)
            if system_parts:
                params["system"] = "\n".join(system_parts)
            if user_assistant_parts:
                params["content"] = "\n".join(user_assistant_parts)

        model = data.get("model")
        if isinstance(model, str) and model:
            params["model"] = model

        return params

    def extract_response_params(self, body: bytes) -> dict[str, str]:
        """Extract scannable parameters from an OpenAI response body.

        Parses the JSON body and extracts:
        - ``content``: Generated content from choices.

        Args:
            body: Raw response body bytes.

        Returns:
            Dictionary of parameter keys to string values.

        Raises:
            ValueError: If the body is not valid JSON.
        """
        data = self._parse_json(body, "response")

        if not isinstance(data, dict):
            return {}

        params: dict[str, str] = {}

        choices = data.get("choices")
        if isinstance(choices, list):
            parts: list[str] = []
            for choice in choices:
                if not isinstance(choice, dict):
                    continue
                # Non-streaming: message.content
                message = choice.get("message")
                if isinstance(message, dict):
                    content = self._extract_content(message.get("content"))
                    if content:
                        parts.append(content)
                # Streaming: delta.content
                delta = choice.get("delta")
                if isinstance(delta, dict):
                    content = self._extract_content(delta.get("content"))
                    if content:
                        parts.append(content)
            if parts:
                params["content"] = "\n".join(parts)

        return params

    def extract_stream_content(self, data_str: str) -> list[str]:
        """Extract content from a streaming SSE data payload.

        Handles the OpenAI streaming format where each SSE event
        contains ``choices[].delta.content``.

        Args:
            data_str: The JSON string after ``data: `` prefix.

        Returns:
            List of content strings found (may be empty).
        """
        parts: list[str] = []

        if data_str.strip() == "[DONE]":
            return parts

        try:
            data = json.loads(data_str)
        except (json.JSONDecodeError, ValueError):
            return parts

        if not isinstance(data, dict):
            return parts

        choices = data.get("choices", [])
        for choice in choices:
            if isinstance(choice, dict):
                delta = choice.get("delta", {})
                if isinstance(delta, dict):
                    content = delta.get("content")
                    if isinstance(content, str):
                        parts.append(content)

        return parts

    @staticmethod
    def _parse_json(body: bytes, context: str) -> Any:
        """Parse JSON from body bytes.

        Args:
            body: Raw bytes.
            context: Description for error messages.

        Returns:
            Parsed JSON value.

        Raises:
            ValueError: If the body is not valid JSON.
        """
        try:
            return json.loads(body)
        except (json.JSONDecodeError, UnicodeDecodeError) as e:
            msg = f"Invalid JSON {context} body: {e}"
            raise ValueError(msg) from e

    @staticmethod
    def _extract_content(content: Any) -> str:
        """Extract text from a message content field.

        Handles both string content and structured content blocks
        (list of dicts with type/text).

        Args:
            content: Message content — string, list, or None.

        Returns:
            Extracted text as a string, or empty string.
        """
        if isinstance(content, str):
            return content
        if isinstance(content, list):
            parts: list[str] = []
            for item in content:
                if isinstance(item, dict) and item.get("type") == "text":
                    text = item.get("text")
                    if isinstance(text, str):
                        parts.append(text)
            return "\n".join(parts)
        return ""
