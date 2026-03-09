"""Request/response scanner for LLM API payloads.

Extracts scannable content from LLM API request and response bodies
and converts them into Guard-compatible action parameters, using
the ScanTarget enum to map content to the right parameter keys.
"""

from __future__ import annotations

import json
from typing import Any


def extract_request_params(body: bytes) -> dict[str, str]:
    """Extract scannable parameters from an LLM API request body.

    Parses the JSON body and extracts:
    - ``messages``: Concatenated content from all messages.
    - ``system``: System prompt if present (OpenAI ``messages`` with
      role=system, or Anthropic top-level ``system`` field).
    - ``content``: All user/assistant message content concatenated.

    Args:
        body: Raw request body bytes.

    Returns:
        Dictionary of parameter keys to string values, suitable for
        passing to ``Guard.check()``.

    Raises:
        ValueError: If the body is not valid JSON.
    """
    try:
        data = json.loads(body)
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        msg = f"Invalid JSON request body: {e}"
        raise ValueError(msg) from e

    if not isinstance(data, dict):
        return {}

    params: dict[str, str] = {}

    # Extract messages content
    messages = data.get("messages")
    if isinstance(messages, list):
        all_content: list[str] = []
        system_parts: list[str] = []
        user_assistant_parts: list[str] = []

        for msg in messages:
            if not isinstance(msg, dict):
                continue
            role = msg.get("role", "")
            content = _extract_content(msg.get("content"))
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

    # Anthropic-style top-level system field
    anthropic_system = data.get("system")
    if isinstance(anthropic_system, str) and anthropic_system:
        # Append to existing system content if any
        if "system" in params:
            params["system"] = params["system"] + "\n" + anthropic_system
        else:
            params["system"] = anthropic_system

    # Model name (useful for policies restricting specific models)
    model = data.get("model")
    if isinstance(model, str) and model:
        params["model"] = model

    return params


def extract_response_params(body: bytes) -> dict[str, str]:
    """Extract scannable parameters from an LLM API response body.

    Parses the JSON body and extracts:
    - ``content``: Generated content from choices/content blocks.

    Args:
        body: Raw response body bytes.

    Returns:
        Dictionary of parameter keys to string values.

    Raises:
        ValueError: If the body is not valid JSON.
    """
    try:
        data = json.loads(body)
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        msg = f"Invalid JSON response body: {e}"
        raise ValueError(msg) from e

    if not isinstance(data, dict):
        return {}

    params: dict[str, str] = {}

    # OpenAI-style: choices[].message.content
    choices = data.get("choices")
    if isinstance(choices, list):
        parts: list[str] = []
        for choice in choices:
            if not isinstance(choice, dict):
                continue
            message = choice.get("message")
            if isinstance(message, dict):
                content = _extract_content(message.get("content"))
                if content:
                    parts.append(content)
            # Also handle delta for streaming chunks
            delta = choice.get("delta")
            if isinstance(delta, dict):
                content = _extract_content(delta.get("content"))
                if content:
                    parts.append(content)
        if parts:
            params["content"] = "\n".join(parts)

    # Anthropic-style: content[].text
    content_blocks = data.get("content")
    if isinstance(content_blocks, list) and "content" not in params:
        parts = []
        for block in content_blocks:
            if isinstance(block, dict) and block.get("type") == "text":
                text = block.get("text")
                if isinstance(text, str):
                    parts.append(text)
        if parts:
            params["content"] = "\n".join(parts)

    return params


def _extract_content(content: Any) -> str:
    """Extract text content from a message content field.

    Handles both string content and structured content blocks
    (list of dicts with type/text).

    Args:
        content: Message content — string, list of blocks, or None.

    Returns:
        Extracted text content as a string, or empty string.
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
