"""E2E tests: Proxy streaming SSE end-to-end (SG-11).

CRITICAL — SSE streaming had production failures. These tests
exercise the full proxy stack with SSE streaming through a real
Starlette app, MockUpstream, and ASGI transport, validating
chunk delivery, header forwarding, timeout behavior, edge cases,
and mixed streaming/non-streaming within a single session.

Test matrix:
    SG-11.1  Streaming headers forwarded correctly
    SG-11.2  All chunks delivered in order
    SG-11.3  Slow upstream no premature timeout
    SG-11.4  Empty stream handled
    SG-11.5  Non-streaming JSON complete
    SG-11.6  Mixed streaming/non-streaming same session
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

import anyio
import httpx
import pytest

from agentguard.proxy.app import create_app
from agentguard.proxy.config import ProxyConfig
from agentguard.proxy.middleware import _StreamContext

if TYPE_CHECKING:
    from collections.abc import AsyncIterator
    from pathlib import Path

    from starlette.applications import Starlette
    from starlette.requests import Request

    from tests.e2e.conftest import MockUpstream


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _sse_chunk(content: str, index: int = 0) -> str:
    """Build an OpenAI-format SSE chunk payload (raw JSON string)."""
    return json.dumps(
        {
            "id": f"chatcmpl-{index}",
            "object": "chat.completion.chunk",
            "choices": [
                {
                    "index": 0,
                    "delta": {"content": content},
                    "finish_reason": None,
                }
            ],
        }
    )


def _sse_done_chunk() -> str:
    """Build an OpenAI-format SSE final chunk (finish_reason=stop)."""
    return json.dumps(
        {
            "id": "chatcmpl-final",
            "object": "chat.completion.chunk",
            "choices": [
                {
                    "index": 0,
                    "delta": {},
                    "finish_reason": "stop",
                }
            ],
        }
    )


def _streaming_body(content: str = "Hello") -> dict[str, Any]:
    """Build a minimal streaming chat completion request body."""
    return {
        "model": "gpt-4",
        "messages": [{"role": "user", "content": content}],
        "stream": True,
    }


def _non_streaming_body(content: str = "Hello") -> dict[str, Any]:
    """Build a minimal non-streaming chat completion request body."""
    return {
        "model": "gpt-4",
        "messages": [{"role": "user", "content": content}],
    }


def _parse_sse_events(raw: str) -> list[str]:
    """Parse raw SSE text into a list of data payloads."""
    events: list[str] = []
    for line in raw.split("\n"):
        stripped = line.strip()
        if stripped.startswith("data: "):
            events.append(stripped[6:])
    return events


# ---------------------------------------------------------------------------
# SG-11.1: Streaming headers forwarded correctly
# ---------------------------------------------------------------------------


@pytest.mark.anyio
async def test_streaming_headers_forwarded(
    proxy_app_with_mock: Starlette,
    mock_upstream: MockUpstream,
) -> None:
    """The proxy forwards SSE streaming responses with correct
    content-type and status code headers from the upstream.
    """
    mock_upstream.set_sse_chunks(
        [
            _sse_chunk("Hello", 0),
            _sse_done_chunk(),
        ]
    )

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=proxy_app_with_mock),
        base_url="http://proxy",
    ) as client:
        resp = await client.post(
            "/v1/chat/completions",
            json=_streaming_body(),
        )

    assert resp.status_code == 200
    content_type = resp.headers.get("content-type", "")
    assert "text/event-stream" in content_type


# ---------------------------------------------------------------------------
# SG-11.2: All chunks delivered in order
# ---------------------------------------------------------------------------


@pytest.mark.anyio
async def test_all_chunks_in_order(
    proxy_app_with_mock: Starlette,
    mock_upstream: MockUpstream,
) -> None:
    """All SSE chunks from the upstream are delivered to the client
    in the correct order, including the [DONE] marker.
    """
    chunks = [
        _sse_chunk("Hello", 0),
        _sse_chunk(" world", 1),
        _sse_chunk("!", 2),
        _sse_done_chunk(),
    ]
    mock_upstream.set_sse_chunks(chunks)

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=proxy_app_with_mock),
        base_url="http://proxy",
    ) as client:
        resp = await client.post(
            "/v1/chat/completions",
            json=_streaming_body(),
        )

    assert resp.status_code == 200
    events = _parse_sse_events(resp.text)

    # Should have all content chunks + done_chunk + [DONE]
    assert len(events) >= 4

    # Verify content order by extracting delta content from each event
    contents: list[str] = []
    for event_data in events:
        if event_data == "[DONE]":
            continue
        try:
            parsed = json.loads(event_data)
            delta_content = (
                parsed.get("choices", [{}])[0].get("delta", {}).get("content")
            )
            if delta_content is not None:
                contents.append(delta_content)
        except (json.JSONDecodeError, IndexError):
            continue

    assert contents == ["Hello", " world", "!"]

    # Verify [DONE] is the last event
    assert events[-1] == "[DONE]"


# ---------------------------------------------------------------------------
# SG-11.3: Slow upstream no premature timeout
# ---------------------------------------------------------------------------


@pytest.mark.anyio
async def test_slow_upstream_no_premature_timeout(
    mock_upstream: MockUpstream,
    tmp_path: Path,
) -> None:
    """A slow upstream that sends chunks with delays should not cause
    a premature timeout. We use a custom mock with asyncio.sleep
    between chunks to simulate a slow upstream.
    """
    from starlette.applications import Starlette
    from starlette.responses import StreamingResponse as StarletteStreamingResponse
    from starlette.routing import Route

    chunks = [
        _sse_chunk("Slow", 0),
        _sse_chunk(" response", 1),
    ]

    async def _slow_handler(request: Request) -> StarletteStreamingResponse:
        body = await request.body()
        mock_upstream.requests.append(
            {
                "method": request.method,
                "path": request.url.path,
                "headers": dict(request.headers),
                "body": body.decode("utf-8", errors="replace") if body else "",
                "query": str(request.url.query),
            }
        )

        async def _slow_stream() -> AsyncIterator[str]:
            for chunk in chunks:
                await anyio.sleep(0.1)
                yield f"data: {chunk}\n\n"
            yield "data: [DONE]\n\n"

        return StarletteStreamingResponse(
            _slow_stream(),
            media_type="text/event-stream",
            status_code=200,
        )

    slow_app = Starlette(
        routes=[
            Route(
                "/{path:path}",
                _slow_handler,
                methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
            ),
        ]
    )

    audit_dir = tmp_path / "audit"
    audit_dir.mkdir(exist_ok=True)

    config = ProxyConfig(
        upstream_base_url="http://mock-upstream",
        audit_dir=str(audit_dir),
        load_builtins=True,
        scan_responses=True,
        timeout=10.0,
    )
    app = create_app(config)
    middleware = app.state.middleware
    transport = httpx.ASGITransport(app=slow_app)

    async def _patched_forward_request(
        method: str, url: str, headers: dict[str, str], body: bytes
    ) -> Any:
        async with httpx.AsyncClient(
            transport=transport, base_url="http://mock-upstream"
        ) as client_inner:
            return await client_inner.request(
                method=method, url=url, headers=headers, content=body
            )

    async def _patched_forward_streaming(
        method: str, url: str, headers: dict[str, str], body: bytes
    ) -> _StreamContext:
        client_inner = httpx.AsyncClient(
            transport=transport, base_url="http://mock-upstream"
        )
        try:
            response = await client_inner.send(
                client_inner.build_request(
                    method=method, url=url, headers=headers, content=body
                ),
                stream=True,
            )
        except Exception:
            await client_inner.aclose()
            raise
        return _StreamContext(client=client_inner, response=response)

    middleware._forward_request = _patched_forward_request
    middleware._forward_streaming = _patched_forward_streaming

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://proxy",
    ) as client:
        resp = await client.post(
            "/v1/chat/completions",
            json=_streaming_body(),
        )

    assert resp.status_code == 200
    events = _parse_sse_events(resp.text)
    contents: list[str] = []
    for event_data in events:
        if event_data == "[DONE]":
            continue
        try:
            parsed = json.loads(event_data)
            delta = parsed.get("choices", [{}])[0].get("delta", {})
            c = delta.get("content")
            if c is not None:
                contents.append(c)
        except (json.JSONDecodeError, IndexError):
            continue

    assert contents == ["Slow", " response"]


# ---------------------------------------------------------------------------
# SG-11.4: Empty stream handled
# ---------------------------------------------------------------------------


@pytest.mark.anyio
async def test_empty_stream_handled(
    proxy_app_with_mock: Starlette,
    mock_upstream: MockUpstream,
) -> None:
    """An upstream that sends only [DONE] with no content chunks
    should be handled gracefully without errors.
    """
    mock_upstream.set_sse_chunks([])  # No content chunks, just [DONE]

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=proxy_app_with_mock),
        base_url="http://proxy",
    ) as client:
        resp = await client.post(
            "/v1/chat/completions",
            json=_streaming_body(),
        )

    assert resp.status_code == 200
    events = _parse_sse_events(resp.text)
    # Should have at least the [DONE] marker
    assert "[DONE]" in events


# ---------------------------------------------------------------------------
# SG-11.5: Non-streaming JSON complete
# ---------------------------------------------------------------------------


@pytest.mark.anyio
async def test_non_streaming_json_complete(
    proxy_app_with_mock: Starlette,
    mock_upstream: MockUpstream,
) -> None:
    """A non-streaming request returns a complete JSON response
    (not SSE), with the full response body intact.
    """
    expected_response = {
        "id": "chatcmpl-abc123",
        "object": "chat.completion",
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": "Hello there!"},
                "finish_reason": "stop",
            }
        ],
    }
    mock_upstream.set_response(expected_response)

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=proxy_app_with_mock),
        base_url="http://proxy",
    ) as client:
        resp = await client.post(
            "/v1/chat/completions",
            json=_non_streaming_body(),
        )

    assert resp.status_code == 200
    body = resp.json()
    assert body["id"] == "chatcmpl-abc123"
    assert body["choices"][0]["message"]["content"] == "Hello there!"
    content_type = resp.headers.get("content-type", "")
    assert "application/json" in content_type


# ---------------------------------------------------------------------------
# SG-11.6: Mixed streaming/non-streaming same session
# ---------------------------------------------------------------------------


@pytest.mark.anyio
async def test_mixed_streaming_non_streaming(
    proxy_app_with_mock: Starlette,
    mock_upstream: MockUpstream,
) -> None:
    """A proxy instance handles both streaming and non-streaming
    requests within the same session without interference.
    """
    transport = httpx.ASGITransport(app=proxy_app_with_mock)

    # --- First request: non-streaming ---
    mock_upstream.set_response(
        {
            "choices": [{"message": {"content": "Non-streaming response"}}],
        }
    )
    async with httpx.AsyncClient(
        transport=transport, base_url="http://proxy"
    ) as client:
        resp1 = await client.post(
            "/v1/chat/completions",
            json=_non_streaming_body("First"),
        )

    assert resp1.status_code == 200
    assert resp1.json()["choices"][0]["message"]["content"] == (
        "Non-streaming response"
    )

    # --- Second request: streaming ---
    mock_upstream.set_sse_chunks(
        [
            _sse_chunk("Streaming", 0),
            _sse_chunk(" reply", 1),
            _sse_done_chunk(),
        ]
    )
    async with httpx.AsyncClient(
        transport=transport, base_url="http://proxy"
    ) as client:
        resp2 = await client.post(
            "/v1/chat/completions",
            json=_streaming_body("Second"),
        )

    assert resp2.status_code == 200
    events = _parse_sse_events(resp2.text)
    contents: list[str] = []
    for event_data in events:
        if event_data == "[DONE]":
            continue
        try:
            parsed = json.loads(event_data)
            c = parsed.get("choices", [{}])[0].get("delta", {}).get("content")
            if c is not None:
                contents.append(c)
        except (json.JSONDecodeError, IndexError):
            continue
    assert contents == ["Streaming", " reply"]

    # --- Third request: non-streaming again ---
    mock_upstream.set_response(
        {
            "choices": [{"message": {"content": "Back to normal"}}],
        }
    )
    async with httpx.AsyncClient(
        transport=transport, base_url="http://proxy"
    ) as client:
        resp3 = await client.post(
            "/v1/chat/completions",
            json=_non_streaming_body("Third"),
        )

    assert resp3.status_code == 200
    assert resp3.json()["choices"][0]["message"]["content"] == "Back to normal"

    # All three requests should have been forwarded
    assert len(mock_upstream.requests) == 3
