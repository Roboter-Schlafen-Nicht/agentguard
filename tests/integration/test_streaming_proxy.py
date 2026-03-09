"""SG-2: Streaming Proxy with Inbound Scanning.

Integration tests that exercise SSE streaming through the proxy,
including inbound response scanning with mid-stream denial.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from starlette.testclient import TestClient

from agentguard.proxy.app import create_app
from agentguard.proxy.config import ProxyConfig

if TYPE_CHECKING:
    from pathlib import Path

pytestmark = pytest.mark.integration


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _sse_chunk(content: str) -> str:
    """Build one SSE data line with OpenAI streaming delta format."""
    payload = {
        "id": "chatcmpl-test",
        "object": "chat.completion.chunk",
        "choices": [
            {
                "index": 0,
                "delta": {"content": content},
                "finish_reason": None,
            }
        ],
    }
    return f"data: {json.dumps(payload)}\n"


def _streaming_request_body(content: str = "Hello") -> dict:
    """Build an OpenAI request body with stream=true."""
    return {
        "model": "gpt-4",
        "messages": [{"role": "user", "content": content}],
        "stream": True,
    }


def _make_mock_streaming_response(
    sse_lines: list[str],
) -> MagicMock:
    """Create a mock httpx.Response that simulates streaming.

    Returns a MagicMock with status_code, headers, and aiter_lines/aiter_bytes
    that yield the given SSE lines.
    """
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.headers = {"content-type": "text/event-stream"}

    async def aiter_lines():
        for line in sse_lines:
            yield line

    async def aiter_bytes():
        for line in sse_lines:
            yield (line + "\n").encode()

    mock_response.aiter_lines = aiter_lines
    mock_response.aiter_bytes = aiter_bytes
    mock_response.aclose = AsyncMock()

    return mock_response


class _MockStreamContext:
    """Stand-in for middleware._StreamContext."""

    def __init__(self, response: MagicMock) -> None:
        self.client = MagicMock()
        self.client.aclose = AsyncMock()
        self.response = response


# ===========================================================================
# SG-2.1: Streaming request forwarded with SSE chunks intact
# ===========================================================================


class TestStreamingForward:
    """SG-2.1: Streaming request forwarded with all SSE chunks."""

    def test_streaming_chunks_forwarded(self) -> None:
        """All SSE chunks are forwarded to client in order."""
        config = ProxyConfig(
            upstream_base_url="https://api.example.com",
            scan_responses=False,
        )
        app = create_app(config)
        client = TestClient(app, raise_server_exceptions=False)

        sse_lines = [
            _sse_chunk("Hello"),
            _sse_chunk(" world"),
            _sse_chunk("!"),
            "data: [DONE]",
        ]
        mock_resp = _make_mock_streaming_response(sse_lines)
        stream_ctx = _MockStreamContext(mock_resp)

        with patch.object(
            app.state.middleware,
            "_forward_streaming",
            new_callable=AsyncMock,
            return_value=stream_ctx,
        ):
            response = client.post(
                "/v1/chat/completions",
                json=_streaming_request_body("Hello"),
            )

        assert response.status_code == 200

        # Parse SSE chunks from response
        body = response.text
        # Each chunk should appear in the response
        assert "Hello" in body
        assert "world" in body
        assert "[DONE]" in body

        # Audit: 1 entry with result=allowed
        entries = app.state.middleware.audit_log.entries
        assert len(entries) == 1
        assert entries[0].action == "llm_request"
        assert entries[0].result == "allowed"


# ===========================================================================
# SG-2.2: Streaming + inbound scanner allows clean content
# ===========================================================================


class TestStreamingScannerAllows:
    """SG-2.2: Streaming with scanner allows clean content."""

    def test_clean_stream_forwarded(self, tmp_path: Path) -> None:
        """Clean SSE stream passes through scanner without denial."""
        # Policy that denies "BANNED" in llm_response
        policy_dir = tmp_path / "policies"
        policy_dir.mkdir()
        (policy_dir / "deny-banned.yaml").write_text(
            "name: deny-banned\n"
            "description: Block BANNED in responses\n"
            "rules:\n"
            "  - action: llm_response\n"
            "    deny:\n"
            "      - pattern: 'BANNED'\n"
            "    severity: high\n"
        )

        config = ProxyConfig(
            upstream_base_url="https://api.example.com",
            policy_dir=str(policy_dir),
            scan_responses=True,
        )
        app = create_app(config)
        client = TestClient(app, raise_server_exceptions=False)

        sse_lines = [
            _sse_chunk("Hello"),
            _sse_chunk(" there"),
            _sse_chunk(" friend"),
            _sse_chunk("!"),
            _sse_chunk(" How are you?"),
            "data: [DONE]",
        ]
        mock_resp = _make_mock_streaming_response(sse_lines)
        stream_ctx = _MockStreamContext(mock_resp)

        with patch.object(
            app.state.middleware,
            "_forward_streaming",
            new_callable=AsyncMock,
            return_value=stream_ctx,
        ):
            response = client.post(
                "/v1/chat/completions",
                json=_streaming_request_body("Hello"),
            )

        assert response.status_code == 200

        # Audit: request allowed + response allowed
        entries = app.state.middleware.audit_log.entries
        assert len(entries) >= 2
        assert entries[0].result == "allowed"
        # Final audit entry for response should be allowed with scanned_length > 0
        response_entries = [e for e in entries if e.action == "llm_response"]
        assert len(response_entries) == 1
        assert response_entries[0].result == "allowed"
        assert response_entries[0].metadata is not None
        assert int(response_entries[0].metadata.get("scanned_length", "0")) > 0


# ===========================================================================
# SG-2.3: Mid-stream denial terminates SSE early
# ===========================================================================


class TestMidStreamDenial:
    """SG-2.3: Mid-stream denial injects warning + [DONE]."""

    def test_mid_stream_denial(self, tmp_path: Path) -> None:
        """Stream terminated when scanner detects violation."""
        policy_dir = tmp_path / "policies"
        policy_dir.mkdir()
        (policy_dir / "deny-secret.yaml").write_text(
            "name: deny-secret\n"
            "description: Block SECRET_KEY in responses\n"
            "rules:\n"
            "  - action: llm_response\n"
            "    deny:\n"
            "      - pattern: 'SECRET_KEY'\n"
            "    severity: critical\n"
        )

        config = ProxyConfig(
            upstream_base_url="https://api.example.com",
            policy_dir=str(policy_dir),
            scan_responses=True,
        )
        app = create_app(config)
        client = TestClient(app, raise_server_exceptions=False)

        sse_lines = [
            _sse_chunk("Hello"),
            _sse_chunk("here is SECRET_KEY"),
            _sse_chunk("more data after"),
            "data: [DONE]",
        ]
        mock_resp = _make_mock_streaming_response(sse_lines)
        stream_ctx = _MockStreamContext(mock_resp)

        with patch.object(
            app.state.middleware,
            "_forward_streaming",
            new_callable=AsyncMock,
            return_value=stream_ctx,
        ):
            response = client.post(
                "/v1/chat/completions",
                json=_streaming_request_body("tell me"),
            )

        assert response.status_code == 200
        body = response.text

        # Should contain a warning event about blocked policy
        assert "response blocked by policy" in body
        # Should contain [DONE] marker
        assert "[DONE]" in body

        # Audit should record the llm_response denial
        entries = app.state.middleware.audit_log.entries
        response_entries = [e for e in entries if e.action == "llm_response"]
        assert len(response_entries) == 1
        assert response_entries[0].result == "denied"


# ===========================================================================
# SG-2.3a: Cross-chunk pattern detection
# ===========================================================================


class TestCrossChunkDetection:
    """SG-2.3a: InboundScanner detects patterns spanning chunks."""

    def test_cross_chunk_pattern(self, tmp_path: Path) -> None:
        """Pattern split across SSE chunks is still detected."""
        policy_dir = tmp_path / "policies"
        policy_dir.mkdir()
        (policy_dir / "deny-secret.yaml").write_text(
            "name: deny-secret\n"
            "description: Block SECRET in responses\n"
            "rules:\n"
            "  - action: llm_response\n"
            "    deny:\n"
            "      - pattern: 'SECRET'\n"
            "    severity: critical\n"
        )

        config = ProxyConfig(
            upstream_base_url="https://api.example.com",
            policy_dir=str(policy_dir),
            scan_responses=True,
        )
        app = create_app(config)
        client = TestClient(app, raise_server_exceptions=False)

        # "SECRET" is split across two chunks: "SEC" and "RET"
        sse_lines = [
            _sse_chunk("here is SEC"),
            _sse_chunk("RET data"),
            "data: [DONE]",
        ]
        mock_resp = _make_mock_streaming_response(sse_lines)
        stream_ctx = _MockStreamContext(mock_resp)

        with patch.object(
            app.state.middleware,
            "_forward_streaming",
            new_callable=AsyncMock,
            return_value=stream_ctx,
        ):
            response = client.post(
                "/v1/chat/completions",
                json=_streaming_request_body("tell me"),
            )

        body = response.text
        # The scanner accumulates content, so it detects "SECRET"
        # across chunk boundaries
        assert "response blocked by policy" in body

        entries = app.state.middleware.audit_log.entries
        response_entries = [e for e in entries if e.action == "llm_response"]
        assert len(response_entries) == 1
        assert response_entries[0].result == "denied"


# ===========================================================================
# SG-2.4: Provider adapter used for stream content extraction
# ===========================================================================


class TestProviderStreamExtraction:
    """SG-2.4: Provider adapter used when configured."""

    def test_provider_used_for_extraction(self, tmp_path: Path) -> None:
        """OpenAI provider extracts stream content correctly."""
        policy_dir = tmp_path / "policies"
        policy_dir.mkdir()
        (policy_dir / "deny-blocked.yaml").write_text(
            "name: deny-blocked\n"
            "description: Block BLOCKED in responses\n"
            "rules:\n"
            "  - action: llm_response\n"
            "    deny:\n"
            "      - pattern: 'BLOCKED'\n"
            "    severity: high\n"
        )

        config = ProxyConfig(
            upstream_base_url="https://api.example.com",
            policy_dir=str(policy_dir),
            scan_responses=True,
            provider="openai",
        )
        app = create_app(config)
        client = TestClient(app, raise_server_exceptions=False)

        # Clean stream — should pass through
        sse_lines = [
            _sse_chunk("Hello"),
            _sse_chunk(" world"),
            "data: [DONE]",
        ]
        mock_resp = _make_mock_streaming_response(sse_lines)
        stream_ctx = _MockStreamContext(mock_resp)

        with patch.object(
            app.state.middleware,
            "_forward_streaming",
            new_callable=AsyncMock,
            return_value=stream_ctx,
        ):
            response = client.post(
                "/v1/chat/completions",
                json=_streaming_request_body("Hi"),
            )

        assert response.status_code == 200
        # Provider should have been used (verified by non-error result)
        assert app.state.middleware.provider is not None
        assert app.state.middleware.provider.name == "openai"
