"""Anthropic Messages API format adapter.

Handles parsing and extraction for the Anthropic ``/v1/messages``
format, supporting the Claude family of models.  The Anthropic format
differs from OpenAI in several key ways:

- System prompt is a top-level ``system`` field (not a message).
- Content can be structured blocks (``text``, ``tool_use``, etc.).
- Responses use a top-level ``content`` array (no ``choices``).
- Streaming uses typed events (``content_block_delta``) instead of
  ``choices[].delta``.
"""

from __future__ import annotations

import json
from typing import Any


class AnthropicProvider:
    """Provider adapter for Anthropic's Messages API.

    Parses request bodies (top-level system + messages array),
    response bodies (top-level content array), and streaming SSE
    deltas (content_block_delta events).
    """

    @property
    def name(self) -> str:
        """Provider identifier."""
        return "anthropic"

    def extract_request_params(
        self, body: bytes, *, seen_count: int | None = None
    ) -> dict[str, str]:
        """Extract scannable parameters from an Anthropic request body.

        Parses the JSON body and extracts:
        - ``messages``: Concatenated content from all messages.
        - ``system``: System prompt (top-level field).
        - ``content``: All user/assistant message content concatenated.
        - ``model``: Model name if present.

        When ``seen_count`` is provided, only messages at index
        ``seen_count`` and beyond are extracted (delta scanning).

        Args:
            body: Raw request body bytes.
            seen_count: Number of messages already scanned.

        Returns:
            Dictionary of parameter keys to string values.

        Raises:
            ValueError: If the body is not valid JSON.
        """
        data = self._parse_json(body, "request")

        if not isinstance(data, dict):
            return {}

        params: dict[str, str] = {}

        # Anthropic system prompt is a top-level field
        system = data.get("system")
        system_text = self._extract_system(system)
        if system_text:
            params["system"] = system_text

        # Messages array
        messages = data.get("messages")
        if isinstance(messages, list):
            if seen_count is not None and seen_count > 0:
                messages = messages[seen_count:]

            all_content: list[str] = []

            for msg in messages:
                if not isinstance(msg, dict):
                    continue
                content = self._extract_content(msg.get("content"))
                if content:
                    all_content.append(content)

            if all_content:
                params["messages"] = "\n".join(all_content)
                params["content"] = "\n".join(all_content)

        model = data.get("model")
        if isinstance(model, str) and model:
            params["model"] = model

        return params

    def extract_response_params(self, body: bytes) -> dict[str, str]:
        """Extract scannable parameters from an Anthropic response.

        Parses the JSON body and extracts:
        - ``content``: Generated text from content blocks.

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

        content = data.get("content")
        if isinstance(content, list):
            parts: list[str] = []
            for block in content:
                if not isinstance(block, dict):
                    continue
                if block.get("type") == "text":
                    text = block.get("text")
                    if isinstance(text, str) and text:
                        parts.append(text)
            if parts:
                params["content"] = "\n".join(parts)

        return params

    def extract_stream_content(self, data_str: str) -> list[str]:
        """Extract content from a streaming SSE data payload.

        Handles the Anthropic streaming format where content arrives
        in ``content_block_delta`` events with ``text_delta`` type.

        Args:
            data_str: The JSON string after ``data: `` prefix.

        Returns:
            List of content strings found (may be empty).
        """
        parts: list[str] = []

        try:
            data = json.loads(data_str)
        except (json.JSONDecodeError, ValueError):
            return parts

        if not isinstance(data, dict):
            return parts

        # Only content_block_delta with text_delta carries content
        if data.get("type") != "content_block_delta":
            return parts

        delta = data.get("delta")
        if not isinstance(delta, dict):
            return parts

        if delta.get("type") != "text_delta":
            return parts

        text = delta.get("text")
        if isinstance(text, str):
            parts.append(text)

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
    def _extract_system(system: Any) -> str:
        """Extract text from the top-level system field.

        Handles both string and structured block formats.

        Args:
            system: System prompt — string, list of blocks, or None.

        Returns:
            Extracted text, or empty string.
        """
        if isinstance(system, str):
            return system
        if isinstance(system, list):
            parts: list[str] = []
            for block in system:
                if isinstance(block, dict) and block.get("type") == "text":
                    text = block.get("text")
                    if isinstance(text, str):
                        parts.append(text)
            return "\n".join(parts)
        return ""

    @staticmethod
    def _extract_content(content: Any) -> str:
        """Extract text from a message content field.

        Handles string content and structured content blocks
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
