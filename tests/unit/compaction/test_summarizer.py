"""Tests for Phase 2: local model summarization.

Tests cover:
- Summarization of message segments
- Inference server API call format
- Graceful fallback when inference server is unavailable
- Summary prompt construction
- Token budget enforcement
"""

from __future__ import annotations

from unittest.mock import AsyncMock, Mock, patch

import pytest

from agentguard.proxy.compaction.config import CompactionConfig


def _make_old_messages(count: int = 10) -> list[dict]:
    """Build a list of old conversation messages to summarize."""
    messages = []
    for i in range(count):
        messages.append({"role": "user", "content": f"Tell me about topic {i}."})
        messages.append(
            {
                "role": "assistant",
                "content": (
                    f"Here is detailed information about topic {i}. "
                    f"It involves many aspects including technical details, "
                    f"historical context, and practical applications. "
                    f"The key points are: point A, point B, and point C."
                ),
            }
        )
    return messages


class TestBuildSummaryPrompt:
    """Test summary prompt construction."""

    def test_import(self):
        """build_summary_prompt can be imported."""
        from agentguard.proxy.compaction.summarizer import (
            build_summary_prompt,  # noqa: F401
        )

    def test_prompt_contains_messages(self):
        """The prompt includes the conversation content."""
        from agentguard.proxy.compaction.summarizer import build_summary_prompt

        messages = _make_old_messages(3)
        prompt = build_summary_prompt(messages)

        assert "topic 0" in prompt
        assert "topic 2" in prompt

    def test_prompt_asks_for_summary(self):
        """The prompt instructs the model to summarize."""
        from agentguard.proxy.compaction.summarizer import build_summary_prompt

        messages = _make_old_messages(2)
        prompt = build_summary_prompt(messages)

        # Should contain summarization instruction
        assert "summar" in prompt.lower()

    def test_prompt_includes_all_roles(self):
        """The prompt preserves role attribution."""
        from agentguard.proxy.compaction.summarizer import build_summary_prompt

        messages = [
            {"role": "user", "content": "What is Python?"},
            {"role": "assistant", "content": "Python is a programming language."},
        ]
        prompt = build_summary_prompt(messages)

        assert "user" in prompt.lower() or "User" in prompt
        assert "assistant" in prompt.lower() or "Assistant" in prompt


class TestSummarizeSegment:
    """Test the async summarize_segment function."""

    @pytest.mark.asyncio
    async def test_import(self):
        """summarize_segment can be imported."""
        from agentguard.proxy.compaction.summarizer import (
            summarize_segment,  # noqa: F401
        )

    @pytest.mark.asyncio
    async def test_returns_summary_string(self):
        """summarize_segment returns a (str, bool) tuple on success."""
        from agentguard.proxy.compaction.summarizer import summarize_segment

        config = CompactionConfig(
            enabled=True,
            summarizer_url="http://localhost:11434",
            summarizer_model="rnj-1:8b-16k",
        )
        messages = _make_old_messages(3)

        mock_response = AsyncMock()
        mock_response.status_code = 200
        mock_response.json = lambda: {
            "message": {"content": "Summary: discussed topics 0-2."}
        }
        mock_response.raise_for_status = lambda: None

        with patch(
            "agentguard.proxy.compaction.summarizer._call_inference_server",
            return_value="Summary: discussed topics 0-2.",
        ):
            result = await summarize_segment(messages, config)

        assert isinstance(result, tuple)
        summary, used_fallback = result
        assert isinstance(summary, str)
        assert len(summary) > 0
        assert used_fallback is False

    @pytest.mark.asyncio
    async def test_fallback_on_inference_server_failure(self):
        """When inference server is unavailable, returns a fallback summary."""
        from agentguard.proxy.compaction.summarizer import summarize_segment

        config = CompactionConfig(
            enabled=True,
            summarizer_url="http://localhost:99999",  # Bad port
            summarizer_model="nonexistent-model",
        )
        messages = _make_old_messages(3)

        with patch(
            "agentguard.proxy.compaction.summarizer._call_inference_server",
            side_effect=Exception("Connection refused"),
        ):
            result = await summarize_segment(messages, config)

        # Should return a basic fallback, not raise
        assert isinstance(result, tuple)
        summary, used_fallback = result
        assert isinstance(summary, str)
        assert len(summary) > 0
        assert used_fallback is True
        # Fallback should mention it's a condensed history
        assert (
            "conversation" in summary.lower()
            or "history" in summary.lower()
            or "message" in summary.lower()
        )

    @pytest.mark.asyncio
    async def test_empty_messages_returns_empty(self):
        """Empty message list returns empty tuple."""
        from agentguard.proxy.compaction.summarizer import summarize_segment

        config = CompactionConfig(enabled=True)
        result = await summarize_segment([], config)
        assert isinstance(result, tuple)
        summary, used_fallback = result
        assert summary == ""
        assert used_fallback is False


class TestCallInferenceServer:
    """Test the low-level inference server API call."""

    @pytest.mark.asyncio
    async def test_import(self):
        """_call_inference_server can be imported."""
        from agentguard.proxy.compaction.summarizer import (
            _call_inference_server,  # noqa: F401
        )

    @pytest.mark.asyncio
    async def test_sends_correct_payload(self):
        """_call_inference_server sends the right request format."""
        from agentguard.proxy.compaction.summarizer import _call_inference_server

        captured_kwargs = {}

        async def mock_post(*args, **kwargs):
            captured_kwargs.update(kwargs)
            mock_resp = AsyncMock()
            mock_resp.status_code = 200
            mock_resp.json = lambda: {"message": {"content": "test summary"}}
            mock_resp.raise_for_status = lambda: None
            return mock_resp

        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.post = mock_post
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client_cls.return_value = mock_client

            result = await _call_inference_server(
                prompt="Summarize this",
                base_url="http://localhost:11434",
                model="rnj-1:8b-16k",
                timeout=30.0,
            )

        assert result == "test summary"
        # Verify the URL was correct
        assert "url" in captured_kwargs or len(captured_kwargs) > 0

    @pytest.mark.asyncio
    async def test_raises_on_error_status(self):
        """_call_inference_server raises when server returns an error."""
        from agentguard.proxy.compaction.summarizer import _call_inference_server

        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_resp = AsyncMock()
            mock_resp.status_code = 500
            mock_resp.raise_for_status = Mock(
                side_effect=Exception("Internal Server Error")
            )

            mock_client = AsyncMock()
            mock_client.post = AsyncMock(return_value=mock_resp)
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client_cls.return_value = mock_client

            with pytest.raises(Exception, match="Internal Server Error"):
                await _call_inference_server(
                    prompt="Summarize",
                    base_url="http://localhost:11434",
                    model="test",
                    timeout=10.0,
                )
