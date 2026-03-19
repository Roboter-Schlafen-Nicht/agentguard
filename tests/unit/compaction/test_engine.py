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
        assert result.phase_used in ("summarization", "hard_cap")

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
            token_budget=2000,  # Tight enough for Phase 2, room for summary
            recent_turns=2,
            truncate_after_turns=2,
            stub_after_turns=3,
            keep_lines=1,
        )
        engine = CompactionEngine(config)

        # Build messages with large user content so Phase 1 alone
        # cannot bring tokens under budget.
        messages = [{"role": "system", "content": "You are an assistant."}]
        for i in range(20):
            messages.append({"role": "user", "content": f"User message {i} " * 80})
            messages.append(
                {"role": "assistant", "content": f"Assistant reply {i} " * 80}
            )

        with patch(
            "agentguard.proxy.compaction.engine.summarize_segment",
            new_callable=AsyncMock,
            return_value=("Summary: worked on tasks 0-15.", False),
        ):
            result = await engine.compact(messages)

        # Should have: system prompt, summary message, then recent turns
        assert result.messages[0]["role"] == "system"
        # Summary message should be present in the output
        found_summary = any(
            "Summary:" in (m.get("content") or "") for m in result.messages
        )
        assert found_summary, "Summary not found in messages"

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


class TestPhase3HardCap:
    """Phase 3: drop oldest non-system messages until under budget."""

    @pytest.mark.asyncio
    async def test_result_under_budget_after_phase3(self):
        """After compaction, tokens_after must be <= token_budget."""
        from agentguard.proxy.compaction.engine import CompactionEngine

        config = CompactionConfig(
            enabled=True,
            token_budget=2000,
            recent_turns=2,
            truncate_after_turns=1,
            stub_after_turns=2,
            keep_lines=1,
        )
        engine = CompactionEngine(config)
        # Create a large conversation — many turns with big user messages
        # that Phase 1 won't shrink (Phase 1 only truncates tool results)
        messages = [{"role": "system", "content": "You are a helpful assistant."}]
        for i in range(40):
            # Large user messages that Phase 1 can't truncate
            messages.append({"role": "user", "content": f"Question {i}: " + "x " * 500})
            messages.append(
                {"role": "assistant", "content": f"Answer {i}: " + "y " * 500}
            )

        with patch(
            "agentguard.proxy.compaction.engine.summarize_segment",
            new_callable=AsyncMock,
            # Summarizer "fails" — returns a still-too-big summary
            return_value=("summary " * 3000, True),
        ):
            result = await engine.compact(messages)

        assert result.tokens_after <= config.token_budget

    @pytest.mark.asyncio
    async def test_system_messages_preserved_during_phase3(self):
        """Phase 3 never drops system messages."""
        from agentguard.proxy.compaction.engine import CompactionEngine

        config = CompactionConfig(
            enabled=True,
            token_budget=500,
            recent_turns=1,
            truncate_after_turns=1,
            stub_after_turns=1,
            keep_lines=1,
        )
        engine = CompactionEngine(config)
        messages = [{"role": "system", "content": "You are a helpful assistant."}]
        for i in range(20):
            messages.append({"role": "user", "content": f"Q{i}: " + "x " * 300})
            messages.append({"role": "assistant", "content": f"A{i}: " + "y " * 300})

        with patch(
            "agentguard.proxy.compaction.engine.summarize_segment",
            new_callable=AsyncMock,
            return_value=("summary " * 2000, True),
        ):
            result = await engine.compact(messages)

        system_msgs = [m for m in result.messages if m["role"] == "system"]
        assert len(system_msgs) >= 1, "System message was dropped"

    @pytest.mark.asyncio
    async def test_phase3_logs_when_dropping(self, caplog):
        """Phase 3 emits a log when it drops messages."""
        import logging

        from agentguard.proxy.compaction.engine import CompactionEngine

        config = CompactionConfig(
            enabled=True,
            token_budget=1000,
            recent_turns=1,
            truncate_after_turns=1,
            stub_after_turns=1,
            keep_lines=1,
        )
        engine = CompactionEngine(config)
        messages = [{"role": "system", "content": "You are a helpful assistant."}]
        for i in range(20):
            messages.append({"role": "user", "content": f"Q{i}: " + "x " * 300})
            messages.append({"role": "assistant", "content": f"A{i}: " + "y " * 300})

        with (
            patch(
                "agentguard.proxy.compaction.engine.summarize_segment",
                new_callable=AsyncMock,
                return_value=("summary " * 2000, True),
            ),
            caplog.at_level(logging.DEBUG, logger="agentguard.proxy.compaction.engine"),
        ):
            await engine.compact(messages)

        phase3_logs = [r for r in caplog.records if "phase3" in r.message.lower()]
        assert len(phase3_logs) >= 1, (
            f"No phase3 log found. Logs: {[r.message for r in caplog.records]}"
        )

    @pytest.mark.asyncio
    async def test_phase3_not_triggered_when_under_budget(self):
        """Phase 3 does NOT run when already under budget after Phase 2."""
        from agentguard.proxy.compaction.engine import CompactionEngine

        config = CompactionConfig(
            enabled=True,
            token_budget=100_000,  # Huge budget
            recent_turns=2,
            truncate_after_turns=1,
            stub_after_turns=2,
            keep_lines=1,
        )
        engine = CompactionEngine(config)
        messages = _make_messages(turns=5, lines_per_tool=5)

        # With 100k budget, this small conversation won't even trigger compaction
        result = await engine.compact(messages)

        # No phase3 log should appear
        assert result.tokens_after <= config.token_budget

    @pytest.mark.asyncio
    async def test_phase3_preserves_most_recent_user_message(self):
        """Phase 3 must keep at least the most recent user message."""
        from agentguard.proxy.compaction.engine import CompactionEngine

        config = CompactionConfig(
            enabled=True,
            token_budget=200,  # Extremely tight
            recent_turns=1,
            truncate_after_turns=1,
            stub_after_turns=1,
            keep_lines=1,
        )
        engine = CompactionEngine(config)
        messages = [{"role": "system", "content": "You are a helpful assistant."}]
        for i in range(20):
            messages.append({"role": "user", "content": f"Q{i}: " + "x " * 300})
            messages.append({"role": "assistant", "content": f"A{i}: " + "y " * 300})

        with patch(
            "agentguard.proxy.compaction.engine.summarize_segment",
            new_callable=AsyncMock,
            return_value=("summary " * 2000, True),
        ):
            result = await engine.compact(messages)

        user_msgs = [m for m in result.messages if m["role"] == "user"]
        assert len(user_msgs) >= 1, "All user messages were dropped"


class TestPhase3ToolPairing:
    """Phase 3 must preserve tool_use / tool_result pairing.

    The Anthropic API requires every tool_result to have a matching
    tool_use in the preceding assistant message.  Phase 3 must drop
    messages in atomic groups: an assistant message with tool_calls
    and ALL its corresponding tool result messages must be dropped
    together or kept together.
    """

    @staticmethod
    def _make_tool_conversation(turns: int = 10) -> list[dict]:
        """Build a conversation with tool_calls / tool results.

        Each turn is: user → assistant(tool_calls) → tool → assistant(text).
        Uses large content to ensure Phase 3 is triggered.
        """
        msgs: list[dict] = [{"role": "system", "content": "You are helpful."}]
        for i in range(turns):
            msgs.append({"role": "user", "content": f"Do task {i} " + "x " * 500})
            call_id = f"call_{i}"
            msgs.append(
                {
                    "role": "assistant",
                    "content": None,
                    "tool_calls": [
                        {
                            "id": call_id,
                            "type": "function",
                            "function": {
                                "name": "bash",
                                "arguments": f'{{"cmd": "echo {i}"}}',
                            },
                        }
                    ],
                }
            )
            msgs.append(
                {
                    "role": "tool",
                    "tool_call_id": call_id,
                    "content": f"output {i} " + "o " * 500,
                }
            )
            msgs.append({"role": "assistant", "content": f"Done {i} " + "d " * 500})
        return msgs

    @staticmethod
    def _make_multi_tool_conversation(turns: int = 10) -> list[dict]:
        """Build conversation where each turn has multiple tool calls.

        Each turn: user → assistant(2 tool_calls) → tool1 → tool2 → assistant(text).
        Uses large content to ensure Phase 3 is triggered.
        """
        msgs: list[dict] = [{"role": "system", "content": "You are helpful."}]
        for i in range(turns):
            msgs.append({"role": "user", "content": f"Multi task {i} " + "x " * 500})
            call_id_a = f"call_{i}_a"
            call_id_b = f"call_{i}_b"
            msgs.append(
                {
                    "role": "assistant",
                    "content": None,
                    "tool_calls": [
                        {
                            "id": call_id_a,
                            "type": "function",
                            "function": {
                                "name": "bash",
                                "arguments": f'{{"cmd": "a_{i}"}}',
                            },
                        },
                        {
                            "id": call_id_b,
                            "type": "function",
                            "function": {
                                "name": "read",
                                "arguments": f'{{"path": "f_{i}"}}',
                            },
                        },
                    ],
                }
            )
            msgs.append(
                {
                    "role": "tool",
                    "tool_call_id": call_id_a,
                    "content": f"output a_{i} " + "o " * 500,
                }
            )
            msgs.append(
                {
                    "role": "tool",
                    "tool_call_id": call_id_b,
                    "content": f"output b_{i} " + "o " * 500,
                }
            )
            msgs.append(
                {
                    "role": "assistant",
                    "content": f"Done multi {i} " + "d " * 500,
                }
            )
        return msgs

    @pytest.mark.asyncio
    async def test_every_tool_result_has_matching_tool_call(self):
        """After Phase 3, every tool message must have a preceding
        assistant with a matching tool_call id."""
        from agentguard.proxy.compaction.engine import CompactionEngine

        config = CompactionConfig(
            enabled=True,
            token_budget=2000,  # Tight enough to trigger Phase 3
            recent_turns=2,
            truncate_after_turns=1,
            stub_after_turns=2,
            keep_lines=1,
        )
        engine = CompactionEngine(config)
        messages = self._make_tool_conversation(turns=15)

        with patch(
            "agentguard.proxy.compaction.engine.summarize_segment",
            new_callable=AsyncMock,
            return_value=("summary " * 3000, True),
        ):
            result = await engine.compact(messages)

        # Verify every tool result has a matching tool_call
        for i, msg in enumerate(result.messages):
            if msg.get("role") == "tool":
                tool_call_id = msg.get("tool_call_id")
                assert tool_call_id is not None, (
                    f"Tool message at index {i} missing tool_call_id"
                )
                # Find the preceding assistant with matching tool_call
                found = False
                for j in range(i - 1, -1, -1):
                    prev = result.messages[j]
                    if prev.get("role") == "assistant" and prev.get("tool_calls"):
                        call_ids = {tc["id"] for tc in prev["tool_calls"]}
                        if tool_call_id in call_ids:
                            found = True
                            break
                assert found, (
                    f"Tool result at index {i} with tool_call_id={tool_call_id} "
                    f"has no matching tool_use in a preceding assistant message. "
                    f"Remaining messages: {[m.get('role') for m in result.messages]}"
                )

    @pytest.mark.asyncio
    async def test_every_tool_call_has_matching_result(self):
        """After Phase 3, every assistant tool_call must have a
        subsequent tool result with matching id (no orphaned calls)."""
        from agentguard.proxy.compaction.engine import CompactionEngine

        config = CompactionConfig(
            enabled=True,
            token_budget=2000,
            recent_turns=2,
            truncate_after_turns=1,
            stub_after_turns=2,
            keep_lines=1,
        )
        engine = CompactionEngine(config)
        messages = self._make_tool_conversation(turns=15)

        with patch(
            "agentguard.proxy.compaction.engine.summarize_segment",
            new_callable=AsyncMock,
            return_value=("summary " * 3000, True),
        ):
            result = await engine.compact(messages)

        # Verify every tool_call has a matching tool result after it
        for i, msg in enumerate(result.messages):
            if msg.get("role") == "assistant" and msg.get("tool_calls"):
                for tc in msg["tool_calls"]:
                    tc_id = tc["id"]
                    found = False
                    for j in range(i + 1, len(result.messages)):
                        nxt = result.messages[j]
                        if (
                            nxt.get("role") == "tool"
                            and nxt.get("tool_call_id") == tc_id
                        ):
                            found = True
                            break
                    assert found, (
                        f"Assistant tool_call at index {i} with id={tc_id} "
                        f"has no matching tool result. "
                        f"Messages: {[m.get('role') for m in result.messages]}"
                    )

    @pytest.mark.asyncio
    async def test_multi_tool_calls_preserved_atomically(self):
        """When assistant has multiple tool_calls, ALL their results
        must be kept or dropped together."""
        from agentguard.proxy.compaction.engine import CompactionEngine

        config = CompactionConfig(
            enabled=True,
            token_budget=3000,
            recent_turns=2,
            truncate_after_turns=1,
            stub_after_turns=2,
            keep_lines=1,
        )
        engine = CompactionEngine(config)
        messages = self._make_multi_tool_conversation(turns=15)

        with patch(
            "agentguard.proxy.compaction.engine.summarize_segment",
            new_callable=AsyncMock,
            return_value=("summary " * 3000, True),
        ):
            result = await engine.compact(messages)

        # Every tool_call must have its result, every tool result must
        # have its preceding assistant with matching tool_call
        for i, msg in enumerate(result.messages):
            if msg.get("role") == "tool":
                tool_call_id = msg.get("tool_call_id")
                found = False
                for j in range(i - 1, -1, -1):
                    prev = result.messages[j]
                    if prev.get("role") == "assistant" and prev.get("tool_calls"):
                        call_ids = {tc["id"] for tc in prev["tool_calls"]}
                        if tool_call_id in call_ids:
                            found = True
                            break
                assert found, f"Multi-tool result at {i} (id={tool_call_id}) orphaned"

            if msg.get("role") == "assistant" and msg.get("tool_calls"):
                for tc in msg["tool_calls"]:
                    tc_id = tc["id"]
                    found = any(
                        r.get("role") == "tool" and r.get("tool_call_id") == tc_id
                        for r in result.messages[i + 1 :]
                    )
                    assert found, f"Multi-tool call at {i} (id={tc_id}) has no result"

    @pytest.mark.asyncio
    async def test_phase3_still_reduces_tokens(self):
        """Phase 3 with atomic removal still brings tokens under budget."""
        from agentguard.proxy.compaction.engine import CompactionEngine

        config = CompactionConfig(
            enabled=True,
            token_budget=2000,
            recent_turns=2,
            truncate_after_turns=1,
            stub_after_turns=2,
            keep_lines=1,
        )
        engine = CompactionEngine(config)
        messages = self._make_tool_conversation(turns=15)

        with patch(
            "agentguard.proxy.compaction.engine.summarize_segment",
            new_callable=AsyncMock,
            return_value=("summary " * 3000, True),
        ):
            result = await engine.compact(messages)

        assert result.tokens_after <= config.token_budget
        assert result.phase_used == "hard_cap"

    @pytest.mark.asyncio
    async def test_tool_result_immediately_after_its_tool_call(self):
        """Tool results must appear immediately after their assistant
        tool_call message (no other messages in between disrupting order)."""
        from agentguard.proxy.compaction.engine import CompactionEngine

        config = CompactionConfig(
            enabled=True,
            token_budget=2000,
            recent_turns=2,
            truncate_after_turns=1,
            stub_after_turns=2,
            keep_lines=1,
        )
        engine = CompactionEngine(config)
        messages = self._make_tool_conversation(turns=15)

        with patch(
            "agentguard.proxy.compaction.engine.summarize_segment",
            new_callable=AsyncMock,
            return_value=("summary " * 3000, True),
        ):
            result = await engine.compact(messages)

        # For each assistant with tool_calls, the very next message(s)
        # must be the tool results
        for i, msg in enumerate(result.messages):
            if msg.get("role") == "assistant" and msg.get("tool_calls"):
                expected_ids = {tc["id"] for tc in msg["tool_calls"]}
                found_ids = set()
                for j in range(i + 1, len(result.messages)):
                    nxt = result.messages[j]
                    if nxt.get("role") == "tool":
                        found_ids.add(nxt.get("tool_call_id"))
                    else:
                        break  # Non-tool message means results ended
                assert expected_ids == found_ids, (
                    f"At index {i}: tool_calls expect {expected_ids} "
                    f"but found results {found_ids}"
                )


class TestHardCapAtomicRemoval:
    """Unit tests for _apply_hard_cap directly, bypassing Phase 1/2.

    These tests construct messages that _apply_hard_cap will receive
    and verify tool_use/tool_result pairing is never broken.
    """

    @pytest.mark.asyncio
    async def test_hard_cap_breaks_tool_pairing_when_dropping_individually(self):
        """REGRESSION: _apply_hard_cap pops messages one at a time,
        which can separate an assistant(tool_calls) from its tool result.

        This test constructs a message array where individual popping
        WILL break pairing, and asserts that pairing is preserved.
        """
        from agentguard.proxy.compaction.engine import CompactionEngine

        # Very tight budget — forces Phase 3 to drop many messages
        config = CompactionConfig(
            enabled=True,
            token_budget=500,
            recent_turns=100,  # Keep ALL turns as "recent" so Phase 2
            # doesn't replace them with summary
            truncate_after_turns=100,
            stub_after_turns=100,
            keep_lines=100,
        )
        engine = CompactionEngine(config)

        # Build messages directly — large enough to exceed budget
        messages = [{"role": "system", "content": "You are helpful."}]
        for i in range(20):
            messages.append({"role": "user", "content": f"Q{i} " + "w " * 200})
            call_id = f"call_{i}"
            messages.append(
                {
                    "role": "assistant",
                    "content": None,
                    "tool_calls": [
                        {
                            "id": call_id,
                            "type": "function",
                            "function": {"name": "bash", "arguments": "{}"},
                        }
                    ],
                }
            )
            messages.append(
                {
                    "role": "tool",
                    "tool_call_id": call_id,
                    "content": f"result {i} " + "r " * 200,
                }
            )
            messages.append({"role": "assistant", "content": f"Done {i} " + "d " * 200})

        # Call compact — Phase 1/2 won't help (recent_turns=100 keeps all)
        # Phase 3 must drop messages to fit budget
        result = await engine.compact(messages)

        assert result.phase_used == "hard_cap", (
            f"Expected phase3 but got {result.phase_used}"
        )

        # Verify EVERY tool result has a matching preceding tool_call
        for i, msg in enumerate(result.messages):
            if msg.get("role") == "tool":
                tool_call_id = msg.get("tool_call_id")
                found = False
                for j in range(i - 1, -1, -1):
                    prev = result.messages[j]
                    if prev.get("role") == "assistant" and prev.get("tool_calls"):
                        call_ids = {tc["id"] for tc in prev["tool_calls"]}
                        if tool_call_id in call_ids:
                            found = True
                            break
                assert found, (
                    f"BROKEN PAIRING: tool result at index {i} "
                    f"(tool_call_id={tool_call_id}) has no matching "
                    f"assistant tool_call. Messages: "
                    f"{
                        [
                            (m.get('role'), m.get('tool_call_id', ''))
                            for m in result.messages
                        ]
                    }"
                )

        # Verify EVERY assistant with tool_calls has all results present
        for i, msg in enumerate(result.messages):
            if msg.get("role") == "assistant" and msg.get("tool_calls"):
                for tc in msg["tool_calls"]:
                    tc_id = tc["id"]
                    found = any(
                        r.get("role") == "tool" and r.get("tool_call_id") == tc_id
                        for r in result.messages[i + 1 :]
                    )
                    assert found, (
                        f"ORPHANED TOOL_CALL: assistant at index {i} "
                        f"has tool_call id={tc_id} with no result"
                    )

    @pytest.mark.asyncio
    async def test_hard_cap_multi_tool_calls_atomic(self):
        """When an assistant has 2+ tool_calls, dropping one tool result
        while keeping another breaks the API contract."""
        from agentguard.proxy.compaction.engine import CompactionEngine

        config = CompactionConfig(
            enabled=True,
            token_budget=500,
            recent_turns=100,
            truncate_after_turns=100,
            stub_after_turns=100,
            keep_lines=100,
        )
        engine = CompactionEngine(config)

        messages = [{"role": "system", "content": "You are helpful."}]
        for i in range(15):
            messages.append({"role": "user", "content": f"Q{i} " + "w " * 200})
            cid_a = f"call_{i}_a"
            cid_b = f"call_{i}_b"
            messages.append(
                {
                    "role": "assistant",
                    "content": None,
                    "tool_calls": [
                        {
                            "id": cid_a,
                            "type": "function",
                            "function": {"name": "bash", "arguments": "{}"},
                        },
                        {
                            "id": cid_b,
                            "type": "function",
                            "function": {"name": "read", "arguments": "{}"},
                        },
                    ],
                }
            )
            messages.append(
                {
                    "role": "tool",
                    "tool_call_id": cid_a,
                    "content": f"a{i} " + "r " * 200,
                }
            )
            messages.append(
                {
                    "role": "tool",
                    "tool_call_id": cid_b,
                    "content": f"b{i} " + "r " * 200,
                }
            )
            messages.append({"role": "assistant", "content": f"Done {i} " + "d " * 200})

        result = await engine.compact(messages)
        assert result.phase_used == "hard_cap"

        # All tool pairing must be intact
        for i, msg in enumerate(result.messages):
            if msg.get("role") == "assistant" and msg.get("tool_calls"):
                expected = {tc["id"] for tc in msg["tool_calls"]}
                actual = set()
                for j in range(i + 1, len(result.messages)):
                    nxt = result.messages[j]
                    if nxt.get("role") == "tool":
                        actual.add(nxt.get("tool_call_id"))
                    else:
                        break
                assert expected == actual, (
                    f"At index {i}: expected tool results {expected}, got {actual}"
                )

    @pytest.mark.asyncio
    async def test_hard_cap_direct_method_orphans_tool_result(self):
        """REGRESSION: _apply_hard_cap drops an assistant(tool_calls)
        message but leaves its tool result orphaned.

        Scenario: dropping the user message (102 tokens) isn't enough,
        so the assistant(tool_calls) (103 tokens) is dropped next.
        That brings us under budget, but the tool result is now
        orphaned — no preceding assistant with matching tool_call.
        """
        from agentguard.proxy.compaction.engine import CompactionEngine

        # Carefully constructed: budget = 206
        # After dropping user1 (102 tok) → 308 tokens, still over
        # After dropping assistant(tc) (103 tok) → 205 tokens, under budget
        # But tool result with call_1 is now orphaned!
        messages = [
            {"role": "system", "content": "sys"},
            {"role": "user", "content": "user1 " + "a " * 200},  # ~102 tok
            {
                "role": "assistant",
                "content": None,
                "tool_calls": [
                    {
                        "id": "call_1",
                        "type": "function",
                        "function": {
                            "name": "bash",
                            "arguments": '{"cmd": "' + "x" * 400 + '"}',
                        },
                    }
                ],
            },  # ~103 tok
            {
                "role": "tool",
                "tool_call_id": "call_1",
                "content": "ok",
            },  # ~1 tok
            {"role": "assistant", "content": "done1 " + "b " * 200},  # ~102 tok
            {"role": "user", "content": "user2 " + "c " * 100},  # ~51 tok
            {"role": "assistant", "content": "done2 " + "d " * 100},  # ~51 tok
        ]

        config = CompactionConfig(enabled=True, token_budget=206)
        engine = CompactionEngine(config)

        result = engine._apply_hard_cap(messages)

        # The result must not have orphaned tool results
        for i, msg in enumerate(result):
            if msg.get("role") == "tool":
                tool_call_id = msg.get("tool_call_id")
                found = False
                for j in range(i - 1, -1, -1):
                    prev = result[j]
                    if (
                        prev.get("role") == "assistant"
                        and prev.get("tool_calls")
                        and tool_call_id in {tc["id"] for tc in prev["tool_calls"]}
                    ):
                        found = True
                        break
                assert found, (
                    f"ORPHANED tool result at index {i} "
                    f"(tool_call_id={tool_call_id}). "
                    f"Roles: {[m.get('role') for m in result]}"
                )

    def test_hard_cap_direct_orphans_tool_call(self):
        """REGRESSION: _apply_hard_cap drops tool result messages
        but leaves the assistant with tool_calls that references them.

        Scenario: the first non-system message is an assistant with
        tool_calls. The loop pops it, but the budget is satisfied
        before the tool result is also removed.
        """
        from agentguard.proxy.compaction.engine import CompactionEngine

        # Construct: assistant(tool_calls, big args) followed by
        # big tool result, then more messages.
        # Budget chosen so that after dropping assistant(tc), we're
        # under budget but the tool result is left.
        messages = [
            {"role": "system", "content": "sys"},
            # No user message first — start with assistant(tool_calls)
            # This simulates mid-conversation after earlier drops
            {
                "role": "assistant",
                "content": None,
                "tool_calls": [
                    {
                        "id": "call_A",
                        "type": "function",
                        "function": {
                            "name": "bash",
                            "arguments": '{"cmd": "' + "y" * 400 + '"}',
                        },
                    }
                ],
            },
            {
                "role": "tool",
                "tool_call_id": "call_A",
                "content": "result_A " + "r " * 200,
            },
            {"role": "assistant", "content": "done " + "d " * 200},
            {"role": "user", "content": "final " + "w " * 100},
            {"role": "assistant", "content": "bye " + "e " * 100},
        ]

        # Budget 307: after dropping assistant(tc) (409→306), under budget.
        # Tool result for call_A is now orphaned at the front.
        config = CompactionConfig(enabled=True, token_budget=307)
        engine = CompactionEngine(config)

        result = engine._apply_hard_cap(messages)

        # Verify no orphaned tool_calls (assistant with tool_calls but no results)
        for i, msg in enumerate(result):
            if msg.get("role") == "assistant" and msg.get("tool_calls"):
                for tc in msg["tool_calls"]:
                    found = any(
                        r.get("role") == "tool" and r.get("tool_call_id") == tc["id"]
                        for r in result[i + 1 :]
                    )
                    assert found, (
                        f"ORPHANED tool_call at index {i} (id={tc['id']}). "
                        f"Roles: {[m.get('role') for m in result]}"
                    )

        # Also verify no orphaned tool results
        for i, msg in enumerate(result):
            if msg.get("role") == "tool":
                tool_call_id = msg.get("tool_call_id")
                found = False
                for j in range(i - 1, -1, -1):
                    prev = result[j]
                    if (
                        prev.get("role") == "assistant"
                        and prev.get("tool_calls")
                        and tool_call_id in {tc["id"] for tc in prev["tool_calls"]}
                    ):
                        found = True
                        break
                assert found, (
                    f"ORPHANED tool result at index {i} "
                    f"(tool_call_id={tool_call_id}). "
                    f"Roles: {[m.get('role') for m in result]}"
                )
