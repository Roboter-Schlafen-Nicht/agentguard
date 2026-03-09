"""SSE streaming response handler for LLM API proxy.

Handles Server-Sent Events (SSE) streaming responses from upstream
LLM APIs, forwarding chunks to the client while optionally
accumulating content for post-stream policy scanning.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

    import httpx


async def stream_sse_response(
    upstream_response: httpx.Response,
    *,
    collect: bool = False,
) -> AsyncIterator[tuple[bytes, str | None]]:
    """Stream SSE chunks from an upstream response.

    Yields each chunk as raw bytes for forwarding to the client.
    If ``collect=True``, also accumulates the content from
    ``data:`` lines and yields the full collected content as the
    second element of the final tuple.

    Args:
        upstream_response: The httpx streaming response.
        collect: Whether to accumulate content for scanning.

    Yields:
        Tuples of ``(chunk_bytes, collected_content_or_none)``.
        ``collected_content_or_none`` is None for all chunks except
        the last one when ``collect=True``.
    """
    import json

    collected_parts: list[str] = []

    async for line in upstream_response.aiter_lines():
        # SSE format: "data: {json}\n\n"
        raw = (line + "\n").encode("utf-8")

        if collect and line.startswith("data: "):
            data_str = line[6:]
            if data_str.strip() != "[DONE]":
                try:
                    data = json.loads(data_str)
                    # OpenAI streaming format
                    if isinstance(data, dict):
                        choices = data.get("choices", [])
                        for choice in choices:
                            if isinstance(choice, dict):
                                delta = choice.get("delta", {})
                                if isinstance(delta, dict):
                                    content = delta.get("content")
                                    if isinstance(content, str):
                                        collected_parts.append(content)
                        # Anthropic streaming format
                        if data.get("type") == "content_block_delta":
                            delta = data.get("delta", {})
                            if isinstance(delta, dict):
                                text = delta.get("text")
                                if isinstance(text, str):
                                    collected_parts.append(text)
                except (json.JSONDecodeError, KeyError):
                    pass

        yield raw, None

    # Yield final collected content
    if collect and collected_parts:
        yield b"", "".join(collected_parts)
