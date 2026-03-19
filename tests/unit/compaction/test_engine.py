"""Tests for CompactionEngine — orchestrates Phase 1 + Phase 2.

Tests cover:
- Engine compacts messages when over budget
- Engine skips compaction when under budget
- Engine uses truncation first, then summarization
- CompactionResult contains before/after metrics
- Engine handles disabled config
"""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from agentguard.proxy.compaction.config import CompactionConfig


def _make_messages(turns: int = 20, lines_per_tool: int = 50) -> list[dict]:
    """Build a message array with given number of turns."""
    messages: list[dict] = [{"role": "system", "content": "You are an assistant."}]

    for i in range(turns):
        messages.append({"role": "user", "content": f"User message {i}"})
        tool_call_id = f"call_{i}"
        messages.append(
            {
                "role": "assistant",
                "content": None,
                "tool_calls": [
                    {
                        "id": tool_call_id,
                        "type": "function",
                        "function": {
                            "name": "bash",
                            "arguments": f'{{"command": "cmd_{i}"}}',
                        },
                    }
                ],
            }
        )
        tool_lines = [f"line {j} of turn {i}" for j in range(lines_per_tool)]
        messages.append(
            {
                "role": "tool",
                "tool_call_id": tool_call_id,
                "content": "\n".join(tool_lines),
            }
        )
        messages.append({"role": "assistant", "content": f"Done with turn {i}."})

    return messages


class TestCompactionEngine:
    """Test the CompactionEngine."""

    def test_import(self):
        """CompactionEngine can be imported."""
        from agentguard.proxy.compaction.engine import CompactionEngine  # noqa: F401

    def test_result_import(self):
        """CompactionResult can be imported."""
        from agentguard.proxy.compaction.engine import CompactionResult  # noqa: F401

    @pytest.mark.asyncio
    async def test_compact_reduces_tokens(self):
        """Engine reduces token count for long conversations."""
        from agentguard.proxy.compaction.engine import CompactionEngine

        config = CompactionConfig(
            enabled=True,
            token_budget=5000,
            recent_turns=5,
            truncate_after_turns=5,
            stub_after_turns=15,
            keep_lines=3,
        )
        engine = CompactionEngine(config)
        messages = _make_messages(turns=25, lines_per_tool=100)

        result = await engine.compact(messages)

        assert result.tokens_before > result.tokens_after
        assert result.tokens_after > 0
        assert len(result.messages) > 0
        assert len(result.messages) <= len(messages)

    @pytest.mark.asyncio
    async def test_compact_preserves_system_prompt(self):
        """System prompt is always first in compacted output."""
        from agentguard.proxy.compaction.engine import CompactionEngine

        config = CompactionConfig(
            enabled=True,
            token_budget=5000,
            recent_turns=3,
        )
        engine = CompactionEngine(config)
        messages = _make_messages(turns=20, lines_per_tool=50)

        result = await engine.compact(messages)

        assert result.messages[0]["role"] == "system"
        assert result.messages[0]["content"] == "You are an assistant."

    @pytest.mark.asyncio
    async def test_compact_under_budget_no_changes(self):
        """When already under budget, messages pass through unchanged."""
        from agentguard.proxy.compaction.engine import CompactionEngine

        config = CompactionConfig(
            enabled=True,
            token_budget=100_000,  # Very high budget
            recent_turns=50,
        )
        engine = CompactionEngine(config)
        messages = _make_messages(turns=3, lines_per_tool=5)

        result = await engine.compact(messages)

        assert result.tokens_before == result.tokens_after
        assert len(result.messages) == len(messages)
        assert result.phase_used == "none"

    @pytest.mark.asyncio
    async def test_compact_disabled_returns_original(self):
        """Disabled config passes messages through."""
        from agentguard.proxy.compaction.engine import CompactionEngine

        config = CompactionConfig(enabled=False)
        engine = CompactionEngine(config)
        messages = _make_messages(turns=20, lines_per_tool=100)

        result = await engine.compact(messages)

        assert len(result.messages) == len(messages)
        assert result.phase_used == "disabled"

    @pytest.mark.asyncio
    async def test_phase1_sufficient_skips_phase2(self):
        """When Phase 1 brings tokens under budget, Phase 2 is skipped."""
        from agentguard.proxy.compaction.engine import CompactionEngine

        config = CompactionConfig(
            enabled=True,
            token_budget=50_000,  # Generous enough that truncation suffices
            recent_turns=5,
            truncate_after_turns=3,
            stub_after_turns=10,
            keep_lines=2,
        )
        engine = CompactionEngine(config)
        messages = _make_messages(turns=20, lines_per_tool=50)

        result = await engine.compact(messages)

        assert result.phase_used in ("truncation", "none")

    @pytest.mark.asyncio
    async def test_phase2_called_when_over_budget(self):
        """Phase 2 summarization is invoked when Phase 1 is insufficient."""
        from agentguard.proxy.compaction.engine import CompactionEngine

        config = CompactionConfig(
            enabled=True,
            token_budget=500,  # Very tight budget to force Phase 2
            recent_turns=2,
            truncate_after_turns=2,
            stub_after_turns=5,
            keep_lines=1,
        )
        engine = CompactionEngine(config)
        messages = _make_messages(turns=20, lines_per_tool=50)

        with patch(
            "agentguard.proxy.compaction.engine.summarize_segment",
            new_callable=AsyncMock,
            return_value=("Summary of earlier conversation.", False),
        ) as mock_summarize:
            result = await engine.compact(messages)

        assert mock_summarize.called
        assert result.phase_used == "summarization"

    @pytest.mark.asyncio
    async def test_result_has_metrics(self):
        """CompactionResult contains useful metrics."""
        from agentguard.proxy.compaction.engine import CompactionEngine

        config = CompactionConfig(
            enabled=True,
            token_budget=5000,
            recent_turns=3,
        )
        engine = CompactionEngine(config)
        messages = _make_messages(turns=15, lines_per_tool=40)

        result = await engine.compact(messages)

        assert isinstance(result.tokens_before, int)
        assert isinstance(result.tokens_after, int)
        assert isinstance(result.messages_before, int)
        assert isinstance(result.messages_after, int)
        assert isinstance(result.phase_used, str)
        assert result.messages_before == len(messages)
        assert result.messages_after == len(result.messages)

    @pytest.mark.asyncio
    async def test_summary_injected_as_system_message(self):
        """When Phase 2 runs, summary appears as a message after system prompt."""
        from agentguard.proxy.compaction.engine import CompactionEngine

        config = CompactionConfig(
            enabled=True,
            token_budget=500,  # Force Phase 2
            recent_turns=2,
            truncate_after_turns=2,
            stub_after_turns=3,
            keep_lines=1,
        )
        engine = CompactionEngine(config)
        messages = _make_messages(turns=20, lines_per_tool=50)

        with patch(
            "agentguard.proxy.compaction.engine.summarize_segment",
            new_callable=AsyncMock,
            return_value=("Summary: worked on tasks 0-15.", False),
        ):
            result = await engine.compact(messages)

        # Should have: system prompt, summary message, then recent turns
        assert result.messages[0]["role"] == "system"
        # Second message should contain the summary
        found_summary = any(
            "Summary:" in m.get("content", "") for m in result.messages[1:5]
        )
        assert found_summary, "Summary not found in early messages"

    @pytest.mark.asyncio
    async def test_summarize_called_with_max_words(self):
        """Engine computes a word budget and passes max_words to summarize_segment."""
        from agentguard.proxy.compaction.engine import CompactionEngine

        config = CompactionConfig(
            enabled=True,
            token_budget=500,  # Very low budget to force summarization
            recent_turns=2,
            truncate_after_turns=2,
            stub_after_turns=3,
            keep_lines=1,
        )
        engine = CompactionEngine(config)
        messages = _make_messages(turns=20, lines_per_tool=50)

        with patch(
            "agentguard.proxy.compaction.engine.summarize_segment",
            new_callable=AsyncMock,
            return_value=("Summary of old turns.", False),
        ) as mock_summarize:
            await engine.compact(messages)

        mock_summarize.assert_called_once()
        _, kwargs = mock_summarize.call_args
        assert "max_words" in kwargs, (
            f"max_words not passed to summarize_segment. kwargs: {kwargs}"
        )
        assert isinstance(kwargs["max_words"], int)
        assert kwargs["max_words"] > 0
