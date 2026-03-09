"""Tests for the SSE streaming response handler."""

from __future__ import annotations

import json

import pytest

from agentguard.policies.guard import Guard
from agentguard.proxy.streaming import stream_sse_response


class _FakeStreamingResponse:
    """Fake httpx.Response with async line iteration."""

    def __init__(self, lines: list[str]) -> None:
        self._lines = lines

    async def aiter_lines(self):
        for line in self._lines:
            yield line


class TestStreamSseResponseNoCollect:
    """Test SSE streaming without content collection."""

    @pytest.mark.anyio
    async def test_yields_raw_bytes_for_each_line(self) -> None:
        """Each SSE line should be yielded as UTF-8 bytes with newline."""
        lines = [
            'data: {"choices": [{"delta": {"content": "Hello"}}]}',
            "",
            'data: {"choices": [{"delta": {"content": " world"}}]}',
            "",
            "data: [DONE]",
            "",
        ]
        resp = _FakeStreamingResponse(lines)
        chunks = [
            (chunk, collected) async for chunk, collected in stream_sse_response(resp)
        ]

        assert len(chunks) == len(lines)
        for chunk_bytes, collected in chunks:
            assert isinstance(chunk_bytes, bytes)
            assert collected is None

    @pytest.mark.anyio
    async def test_empty_stream(self) -> None:
        """Empty stream should yield nothing."""
        resp = _FakeStreamingResponse([])
        chunks = [(c, s) async for c, s in stream_sse_response(resp)]
        assert len(chunks) == 0

    @pytest.mark.anyio
    async def test_non_data_lines_forwarded(self) -> None:
        """Non-data SSE lines (comments, event types) should pass through."""
        lines = [
            ": this is a comment",
            "event: message",
            'data: {"choices": []}',
        ]
        resp = _FakeStreamingResponse(lines)
        chunks = [(c, s) async for c, s in stream_sse_response(resp)]

        assert len(chunks) == 3
        assert chunks[0][0] == b": this is a comment\n"
        assert chunks[1][0] == b"event: message\n"


class TestStreamSseResponseCollect:
    """Test SSE streaming with content collection enabled."""

    @pytest.mark.anyio
    async def test_collects_openai_content(self) -> None:
        """Should collect content from OpenAI streaming delta format."""
        lines = [
            "data: " + json.dumps({"choices": [{"delta": {"content": "Hello"}}]}),
            "data: " + json.dumps({"choices": [{"delta": {"content": " world"}}]}),
            "data: [DONE]",
        ]
        resp = _FakeStreamingResponse(lines)
        chunks = [(c, s) async for c, s in stream_sse_response(resp, collect=True)]

        # All intermediate chunks should have None for collected
        assert all(c[1] is None for c in chunks[:-1])
        # Final chunk should have collected content
        last_chunk, collected = chunks[-1]
        assert last_chunk == b""
        assert collected == "Hello world"

    @pytest.mark.anyio
    async def test_collects_anthropic_content(self) -> None:
        """Should collect content from Anthropic streaming delta format."""
        lines = [
            "data: "
            + json.dumps({"type": "content_block_delta", "delta": {"text": "Hello"}}),
            "data: "
            + json.dumps({"type": "content_block_delta", "delta": {"text": " there"}}),
            "data: [DONE]",
        ]
        resp = _FakeStreamingResponse(lines)
        chunks = [(c, s) async for c, s in stream_sse_response(resp, collect=True)]

        last_chunk, collected = chunks[-1]
        assert last_chunk == b""
        assert collected == "Hello there"

    @pytest.mark.anyio
    async def test_mixed_openai_and_anthropic_deltas(self) -> None:
        """Should handle both OpenAI and Anthropic formats in same stream."""
        lines = [
            "data: " + json.dumps({"choices": [{"delta": {"content": "A"}}]}),
            "data: "
            + json.dumps({"type": "content_block_delta", "delta": {"text": "B"}}),
            "data: [DONE]",
        ]
        resp = _FakeStreamingResponse(lines)
        chunks = [(c, s) async for c, s in stream_sse_response(resp, collect=True)]

        _last_chunk, collected = chunks[-1]
        assert collected == "AB"

    @pytest.mark.anyio
    async def test_no_content_in_deltas(self) -> None:
        """Deltas without content should not add to collected text."""
        lines = [
            "data: " + json.dumps({"choices": [{"delta": {"role": "assistant"}}]}),
            "data: " + json.dumps({"choices": [{"delta": {}}]}),
            "data: [DONE]",
        ]
        resp = _FakeStreamingResponse(lines)
        chunks = [(c, s) async for c, s in stream_sse_response(resp, collect=True)]

        # No final collection chunk since collected_parts is empty
        assert all(c[1] is None for c in chunks)

    @pytest.mark.anyio
    async def test_malformed_json_skipped(self) -> None:
        """Malformed JSON data lines should be silently skipped."""
        lines = [
            "data: {invalid json}",
            "data: " + json.dumps({"choices": [{"delta": {"content": "ok"}}]}),
            "data: [DONE]",
        ]
        resp = _FakeStreamingResponse(lines)
        chunks = [(c, s) async for c, s in stream_sse_response(resp, collect=True)]

        _last_chunk, collected = chunks[-1]
        assert collected == "ok"

    @pytest.mark.anyio
    async def test_done_marker_not_collected(self) -> None:
        """The [DONE] marker should not be parsed as JSON."""
        lines = [
            "data: " + json.dumps({"choices": [{"delta": {"content": "x"}}]}),
            "data: [DONE]",
        ]
        resp = _FakeStreamingResponse(lines)
        chunks = [(c, s) async for c, s in stream_sse_response(resp, collect=True)]

        _last_chunk, collected = chunks[-1]
        assert collected == "x"

    @pytest.mark.anyio
    async def test_non_dict_data_skipped(self) -> None:
        """Non-dict JSON data (arrays, strings) should be skipped."""
        lines = [
            'data: ["not", "a", "dict"]',
            'data: "just a string"',
            "data: " + json.dumps({"choices": [{"delta": {"content": "ok"}}]}),
            "data: [DONE]",
        ]
        resp = _FakeStreamingResponse(lines)
        chunks = [(c, s) async for c, s in stream_sse_response(resp, collect=True)]

        _last_chunk, collected = chunks[-1]
        assert collected == "ok"

    @pytest.mark.anyio
    async def test_non_dict_choices_skipped(self) -> None:
        """Choices that are not dicts should be skipped."""
        lines = [
            "data: " + json.dumps({"choices": ["not-a-dict"]}),
            "data: " + json.dumps({"choices": [{"delta": {"content": "ok"}}]}),
            "data: [DONE]",
        ]
        resp = _FakeStreamingResponse(lines)
        chunks = [(c, s) async for c, s in stream_sse_response(resp, collect=True)]

        _last_chunk, collected = chunks[-1]
        assert collected == "ok"

    @pytest.mark.anyio
    async def test_non_dict_delta_skipped(self) -> None:
        """Delta that is not a dict should be skipped."""
        lines = [
            "data: " + json.dumps({"choices": [{"delta": "not-a-dict"}]}),
            "data: " + json.dumps({"choices": [{"delta": {"content": "ok"}}]}),
            "data: [DONE]",
        ]
        resp = _FakeStreamingResponse(lines)
        chunks = [(c, s) async for c, s in stream_sse_response(resp, collect=True)]

        _last_chunk, collected = chunks[-1]
        assert collected == "ok"

    @pytest.mark.anyio
    async def test_non_string_content_skipped(self) -> None:
        """Content that is not a string should be skipped."""
        lines = [
            "data: " + json.dumps({"choices": [{"delta": {"content": 42}}]}),
            "data: " + json.dumps({"choices": [{"delta": {"content": "ok"}}]}),
            "data: [DONE]",
        ]
        resp = _FakeStreamingResponse(lines)
        chunks = [(c, s) async for c, s in stream_sse_response(resp, collect=True)]

        _last_chunk, collected = chunks[-1]
        assert collected == "ok"

    @pytest.mark.anyio
    async def test_anthropic_non_dict_delta_skipped(self) -> None:
        """Anthropic delta that is not a dict should be skipped."""
        lines = [
            "data: "
            + json.dumps({"type": "content_block_delta", "delta": "not-a-dict"}),
            "data: "
            + json.dumps({"type": "content_block_delta", "delta": {"text": "ok"}}),
            "data: [DONE]",
        ]
        resp = _FakeStreamingResponse(lines)
        chunks = [(c, s) async for c, s in stream_sse_response(resp, collect=True)]

        _last_chunk, collected = chunks[-1]
        assert collected == "ok"

    @pytest.mark.anyio
    async def test_anthropic_non_string_text_skipped(self) -> None:
        """Anthropic text that is not a string should be skipped."""
        lines = [
            "data: "
            + json.dumps({"type": "content_block_delta", "delta": {"text": 123}}),
            "data: "
            + json.dumps({"type": "content_block_delta", "delta": {"text": "ok"}}),
            "data: [DONE]",
        ]
        resp = _FakeStreamingResponse(lines)
        chunks = [(c, s) async for c, s in stream_sse_response(resp, collect=True)]

        _last_chunk, collected = chunks[-1]
        assert collected == "ok"

    @pytest.mark.anyio
    async def test_collect_false_no_final_chunk(self) -> None:
        """With collect=False, no final collected content chunk should appear."""
        lines = [
            "data: " + json.dumps({"choices": [{"delta": {"content": "x"}}]}),
            "data: [DONE]",
        ]
        resp = _FakeStreamingResponse(lines)
        chunks = [(c, s) async for c, s in stream_sse_response(resp, collect=False)]

        # All collected values should be None
        assert all(c[1] is None for c in chunks)

    @pytest.mark.anyio
    async def test_multiple_choices_collected(self) -> None:
        """Multiple choices in a single chunk should all be collected."""
        lines = [
            "data: "
            + json.dumps(
                {
                    "choices": [
                        {"delta": {"content": "A"}},
                        {"delta": {"content": "B"}},
                    ]
                }
            ),
            "data: [DONE]",
        ]
        resp = _FakeStreamingResponse(lines)
        chunks = [(c, s) async for c, s in stream_sse_response(resp, collect=True)]

        _last_chunk, collected = chunks[-1]
        assert collected == "AB"


# ===========================================================================
# Tests: stream_sse_response with InboundScanner
# ===========================================================================


class TestStreamSseResponseWithScanner:
    """Test SSE streaming with an InboundScanner for response scanning."""

    @staticmethod
    def _make_scanner_guard(pattern: str) -> Guard:
        """Create a Guard with a single llm_response deny rule."""
        import re

        from agentguard.policies.models import Policy, Rule

        rule = Rule(
            action_kind="llm_response",
            deny_patterns=[re.compile(pattern)],
            severity="high",
            description="Test deny rule",
        )
        policy = Policy(name="test-policy", rules=[rule], description="Test")
        guard = Guard()
        guard.add_policy(policy)
        return guard

    @pytest.mark.anyio
    async def test_scanner_benign_stream_passes_through(self) -> None:
        """Scanner should not interfere with benign content."""
        from agentguard.proxy.inbound import InboundScanner

        guard = self._make_scanner_guard(r"HARMFUL_PATTERN")
        scanner = InboundScanner(guard)

        lines = [
            "data: " + json.dumps({"choices": [{"delta": {"content": "Hello"}}]}),
            "data: " + json.dumps({"choices": [{"delta": {"content": " world"}}]}),
            "data: [DONE]",
        ]
        resp = _FakeStreamingResponse(lines)
        chunks = [(c, s) async for c, s in stream_sse_response(resp, scanner=scanner)]

        # All chunks forwarded, no early termination
        assert len(chunks) == 3
        # Scanner should have accumulated the content
        assert scanner.accumulated_content == "Hello world"

    @pytest.mark.anyio
    async def test_scanner_denies_harmful_content(self) -> None:
        """Scanner should stop stream when harmful content is detected."""
        from agentguard.proxy.inbound import InboundScanner

        guard = self._make_scanner_guard(r"HARMFUL")
        scanner = InboundScanner(guard)

        lines = [
            "data: " + json.dumps({"choices": [{"delta": {"content": "ok "}}]}),
            "data: " + json.dumps({"choices": [{"delta": {"content": "HARMFUL"}}]}),
            "data: " + json.dumps({"choices": [{"delta": {"content": " more"}}]}),
            "data: [DONE]",
        ]
        resp = _FakeStreamingResponse(lines)
        chunks = [(c, s) async for c, s in stream_sse_response(resp, scanner=scanner)]

        # First chunk passes, second triggers denial.
        # After denial: warning event + [DONE] are injected, stream stops.
        # The harmful chunk itself is forwarded (already sent to client),
        # then the warning and done markers follow.
        # Total: chunk1 (ok) + chunk2 (HARMFUL) + warning + done = 4
        assert len(chunks) == 4

        # Last two chunks should be the warning event and [DONE]
        warning_bytes = chunks[-2][0]
        assert b"error" in warning_bytes or b"blocked" in warning_bytes

        done_bytes = chunks[-1][0]
        assert b"[DONE]" in done_bytes

    @pytest.mark.anyio
    async def test_scanner_denial_stops_iteration(self) -> None:
        """After scanner denial, remaining upstream lines should not be yielded."""
        from agentguard.proxy.inbound import InboundScanner

        guard = self._make_scanner_guard(r"STOP")
        scanner = InboundScanner(guard)

        lines = [
            "data: " + json.dumps({"choices": [{"delta": {"content": "STOP"}}]}),
            "data: " + json.dumps({"choices": [{"delta": {"content": "more1"}}]}),
            "data: " + json.dumps({"choices": [{"delta": {"content": "more2"}}]}),
            "data: [DONE]",
        ]
        resp = _FakeStreamingResponse(lines)
        chunks = [(c, s) async for c, s in stream_sse_response(resp, scanner=scanner)]

        # chunk1 (STOP) + warning + done = 3, remaining lines NOT yielded
        assert len(chunks) == 3

    @pytest.mark.anyio
    async def test_scanner_cross_chunk_detection(self) -> None:
        """Scanner should detect patterns spanning multiple chunks."""
        from agentguard.proxy.inbound import InboundScanner

        guard = self._make_scanner_guard(r"HARMFUL_CONTENT")
        scanner = InboundScanner(guard)

        lines = [
            "data: " + json.dumps({"choices": [{"delta": {"content": "HARMFUL"}}]}),
            "data: " + json.dumps({"choices": [{"delta": {"content": "_CONTENT"}}]}),
            "data: " + json.dumps({"choices": [{"delta": {"content": " safe"}}]}),
            "data: [DONE]",
        ]
        resp = _FakeStreamingResponse(lines)
        chunks = [(c, s) async for c, s in stream_sse_response(resp, scanner=scanner)]

        # chunk1 (HARMFUL) passes, chunk2 (_CONTENT) triggers denial.
        # After denial: warning + done injected. chunk3 and DONE not forwarded.
        assert len(chunks) == 4  # chunk1 + chunk2 + warning + done

    @pytest.mark.anyio
    async def test_scanner_with_anthropic_format(self) -> None:
        """Scanner should work with Anthropic SSE format."""
        from agentguard.proxy.inbound import InboundScanner

        guard = self._make_scanner_guard(r"SECRET")
        scanner = InboundScanner(guard)

        lines = [
            "data: "
            + json.dumps({"type": "content_block_delta", "delta": {"text": "ok "}}),
            "data: "
            + json.dumps({"type": "content_block_delta", "delta": {"text": "SECRET"}}),
            "data: "
            + json.dumps({"type": "content_block_delta", "delta": {"text": " more"}}),
            "data: [DONE]",
        ]
        resp = _FakeStreamingResponse(lines)
        chunks = [(c, s) async for c, s in stream_sse_response(resp, scanner=scanner)]

        # chunk1 + chunk2 + warning + done = 4
        assert len(chunks) == 4
        warning_bytes = chunks[-2][0]
        assert b"blocked" in warning_bytes or b"error" in warning_bytes

    @pytest.mark.anyio
    async def test_scanner_none_parameter_same_as_no_scanner(self) -> None:
        """Passing scanner=None should behave like no scanner."""
        lines = [
            "data: " + json.dumps({"choices": [{"delta": {"content": "x"}}]}),
            "data: [DONE]",
        ]
        resp = _FakeStreamingResponse(lines)
        chunks = [(c, s) async for c, s in stream_sse_response(resp, scanner=None)]

        assert len(chunks) == 2
        assert all(c[1] is None for c in chunks)

    @pytest.mark.anyio
    async def test_scanner_and_collect_not_combined(self) -> None:
        """Scanner supersedes collect — collected field is always None."""
        from agentguard.proxy.inbound import InboundScanner

        guard = self._make_scanner_guard(r"NEVER_MATCHES")
        scanner = InboundScanner(guard)

        lines = [
            "data: " + json.dumps({"choices": [{"delta": {"content": "Hi"}}]}),
            "data: [DONE]",
        ]
        resp = _FakeStreamingResponse(lines)
        chunks = [
            (c, s)
            async for c, s in stream_sse_response(resp, collect=True, scanner=scanner)
        ]

        # When scanner is active, the collected field should be None
        assert all(c[1] is None for c in chunks)


# ===========================================================================
# Tests: stream_sse_response with Provider
# ===========================================================================


class TestStreamSseResponseWithProvider:
    """Test SSE streaming with a Provider for content extraction."""

    @pytest.mark.anyio
    async def test_provider_extracts_content_for_collect(self) -> None:
        """Provider should be used for content extraction when collecting."""
        from agentguard.proxy.providers.openai import OpenAIProvider

        provider = OpenAIProvider()
        lines = [
            "data: " + json.dumps({"choices": [{"delta": {"content": "Hello"}}]}),
            "data: " + json.dumps({"choices": [{"delta": {"content": " world"}}]}),
            "data: [DONE]",
        ]
        resp = _FakeStreamingResponse(lines)
        chunks = [
            (c, s)
            async for c, s in stream_sse_response(resp, collect=True, provider=provider)
        ]

        _last_chunk, collected = chunks[-1]
        assert collected == "Hello world"

    @pytest.mark.anyio
    async def test_provider_extracts_content_for_scanner(self) -> None:
        """Provider should be used for content extraction with scanner."""
        import re

        from agentguard.policies.models import Policy, Rule
        from agentguard.proxy.inbound import InboundScanner
        from agentguard.proxy.providers.openai import OpenAIProvider

        rule = Rule(
            action_kind="llm_response",
            deny_patterns=[re.compile(r"BLOCKED")],
            severity="high",
            description="Test deny rule",
        )
        policy = Policy(name="test-policy", rules=[rule], description="Test")
        guard = Guard()
        guard.add_policy(policy)
        scanner = InboundScanner(guard)
        provider = OpenAIProvider()

        lines = [
            "data: " + json.dumps({"choices": [{"delta": {"content": "ok "}}]}),
            "data: " + json.dumps({"choices": [{"delta": {"content": "BLOCKED"}}]}),
            "data: " + json.dumps({"choices": [{"delta": {"content": " more"}}]}),
            "data: [DONE]",
        ]
        resp = _FakeStreamingResponse(lines)
        chunks = [
            (c, s)
            async for c, s in stream_sse_response(
                resp, scanner=scanner, provider=provider
            )
        ]

        # Should detect denial: chunk1 + chunk2 + warning + done = 4
        assert len(chunks) == 4
        assert b"blocked" in chunks[-2][0] or b"error" in chunks[-2][0]

    @pytest.mark.anyio
    async def test_provider_none_uses_fallback(self) -> None:
        """Passing provider=None should fall back to _extract_content_parts."""
        lines = [
            "data: " + json.dumps({"choices": [{"delta": {"content": "Hello"}}]}),
            "data: [DONE]",
        ]
        resp = _FakeStreamingResponse(lines)
        chunks = [
            (c, s)
            async for c, s in stream_sse_response(resp, collect=True, provider=None)
        ]

        _last_chunk, collected = chunks[-1]
        assert collected == "Hello"
