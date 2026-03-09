"""SSE streaming response handler for LLM API proxy.

Handles Server-Sent Events (SSE) streaming responses from upstream
LLM APIs, forwarding chunks to the client while optionally
accumulating content for post-stream policy scanning or real-time
inbound scanning.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

    import httpx

    from agentguard.proxy.inbound import InboundScanner
    from agentguard.proxy.providers import Provider


def _extract_content_parts(data_str: str) -> list[str]:
    """Extract content strings from a JSON SSE data payload.

    Supports both OpenAI and Anthropic streaming delta formats.

    Args:
        data_str: The JSON string after ``data: `` prefix.

    Returns:
        List of content strings found in the payload (may be empty).
    """
    import json

    parts: list[str] = []

    if data_str.strip() == "[DONE]":
        return parts

    try:
        data = json.loads(data_str)
    except (json.JSONDecodeError, KeyError):
        return parts

    if not isinstance(data, dict):
        return parts

    # OpenAI streaming format
    choices = data.get("choices", [])
    for choice in choices:
        if isinstance(choice, dict):
            delta = choice.get("delta", {})
            if isinstance(delta, dict):
                content = delta.get("content")
                if isinstance(content, str):
                    parts.append(content)

    # Anthropic streaming format
    if data.get("type") == "content_block_delta":
        delta = data.get("delta", {})
        if isinstance(delta, dict):
            text = delta.get("text")
            if isinstance(text, str):
                parts.append(text)

    return parts


async def stream_sse_response(
    upstream_response: httpx.Response,
    *,
    collect: bool = False,
    scanner: InboundScanner | None = None,
    provider: Provider | None = None,
) -> AsyncIterator[tuple[bytes, str | None]]:
    """Stream SSE chunks from an upstream response.

    Yields each chunk as raw bytes for forwarding to the client.
    If ``collect=True``, also accumulates the content from
    ``data:`` lines and yields the full collected content as the
    second element of the final tuple.

    If ``scanner`` is provided, each content chunk is fed to the
    scanner for real-time policy evaluation.  When the scanner
    detects a violation, a warning SSE event and ``[DONE]`` marker
    are yielded and the stream is terminated early.  When a scanner
    is active, it supersedes ``collect`` — no final collected
    content chunk is produced.

    If ``provider`` is given, its ``extract_stream_content()``
    method is used for content extraction instead of the built-in
    ``_extract_content_parts()`` fallback.

    Args:
        upstream_response: The httpx streaming response.
        collect: Whether to accumulate content for scanning.
        scanner: Optional inbound scanner for real-time scanning.
        provider: Optional provider adapter for content extraction.

    Yields:
        Tuples of ``(chunk_bytes, collected_content_or_none)``.
        ``collected_content_or_none`` is None for all chunks except
        the last one when ``collect=True`` and ``scanner`` is None.
    """
    import json

    collected_parts: list[str] = []
    use_collect = collect and scanner is None

    async for line in upstream_response.aiter_lines():
        # SSE format: "data: {json}\n\n"
        raw = (line + "\n").encode("utf-8")

        if line.startswith("data: "):
            data_str = line[6:]
            if provider is not None:
                parts = provider.extract_stream_content(data_str)
            else:
                parts = _extract_content_parts(data_str)

            if use_collect:
                collected_parts.extend(parts)

            if scanner is not None and parts:
                content_text = "".join(parts)
                scan_result = scanner.feed(content_text)
                if scan_result is not None and scan_result.denied:
                    # Yield the current chunk (already received from upstream)
                    yield raw, None
                    # Inject warning event
                    warning = json.dumps(
                        {
                            "error": "response blocked by policy",
                            "policy": scan_result.denied_by,
                            "reason": scan_result.reason,
                        }
                    )
                    yield (f"data: {warning}\n").encode(), None
                    # Inject [DONE] marker
                    yield b"data: [DONE]\n", None
                    return

        yield raw, None

    # Yield final collected content (only when collect=True and no scanner)
    if use_collect and collected_parts:
        yield b"", "".join(collected_parts)
