"""Tests for Phase 1: rule-based context truncation.

Tests cover:
- Turn counting (user messages as boundaries)
- Tool result truncation for old turns
- Tool result stubbing for very old turns
- Recent turns preserved verbatim
- System prompt always preserved
- Deduplication of repeated file reads
- Edge cases: empty messages, no tool calls, all recent
- Token estimation before/after
"""

from __future__ import annotations

import pytest

from agentguard.proxy.compaction.config import CompactionConfig


def _make_messages(
    *,
    system: str = "You are a helpful assistant.",
    turns: int = 20,
    tool_content_lines: int = 50,
) -> list[dict]:
    """Build a realistic OpenAI-format message array.

    Each "turn" is: user message + assistant message with tool_calls +
    tool result message + assistant follow-up.

    Args:
        system: System prompt content.
        turns: Number of user/assistant turn pairs to generate.
        tool_content_lines: Number of lines in each tool result.

    Returns:
        List of message dicts in OpenAI chat format.
    """
    messages: list[dict] = [{"role": "system", "content": system}]

    for i in range(turns):
        # User asks something
        messages.append({"role": "user", "content": f"User message {i}"})

        # Assistant makes a tool call
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
                            "arguments": f'{{"command": "command_{i}"}}',
                        },
                    }
                ],
            }
        )

        # Tool result (many lines)
        tool_lines = [f"output line {j} of turn {i}" for j in range(tool_content_lines)]
        messages.append(
            {
                "role": "tool",
                "tool_call_id": tool_call_id,
                "content": "\n".join(tool_lines),
            }
        )

        # Assistant response
        messages.append(
            {
                "role": "assistant",
                "content": f"I ran command_{i}. Here's what happened in turn {i}.",
            }
        )

    return messages


def _make_file_read_messages(*, reads: int = 5) -> list[dict]:
    """Build messages with repeated file reads of the same file.

    Simulates reading the same file multiple times across turns.
    """
    messages: list[dict] = [
        {"role": "system", "content": "System prompt."},
    ]

    for i in range(reads):
        messages.append({"role": "user", "content": f"Read the file again (#{i})"})
        tool_call_id = f"call_read_{i}"
        messages.append(
            {
                "role": "assistant",
                "content": None,
                "tool_calls": [
                    {
                        "id": tool_call_id,
                        "type": "function",
                        "function": {
                            "name": "read",
                            "arguments": '{"filePath": "/src/main.py"}',
                        },
                    }
                ],
            }
        )
        messages.append(
            {
                "role": "tool",
                "tool_call_id": tool_call_id,
                "content": f"# main.py version {i}\ndef main():\n    print('v{i}')\n",
            }
        )
        messages.append(
            {
                "role": "assistant",
                "content": f"I read main.py (version {i}).",
            }
        )

    return messages


class TestTruncateMessages:
    """Test the truncate_messages function."""

    def test_import(self):
        """truncate_messages can be imported."""
        from agentguard.proxy.compaction.truncator import truncate_messages  # noqa: F401

    def test_empty_messages_returns_empty(self):
        """Empty input returns empty output."""
        from agentguard.proxy.compaction.truncator import truncate_messages

        config = CompactionConfig(enabled=True, recent_turns=5)
        result = truncate_messages([], config)
        assert result == []

    def test_system_prompt_always_preserved(self):
        """System prompt is never removed or modified."""
        from agentguard.proxy.compaction.truncator import truncate_messages

        messages = _make_messages(turns=20)
        config = CompactionConfig(enabled=True, recent_turns=5)
        result = truncate_messages(messages, config)

        assert result[0]["role"] == "system"
        assert result[0]["content"] == "You are a helpful assistant."

    def test_recent_turns_preserved_verbatim(self):
        """Messages within recent_turns are not modified."""
        from agentguard.proxy.compaction.truncator import truncate_messages

        messages = _make_messages(turns=20, tool_content_lines=50)
        config = CompactionConfig(enabled=True, recent_turns=5)
        result = truncate_messages(messages, config)

        # The last 5 turns should be identical to the original
        # Each turn = 4 messages (user + assistant+tool_calls + tool + assistant)
        original_last_5 = messages[-(5 * 4) :]
        result_last = result[-(5 * 4) :]

        for orig, comp in zip(original_last_5, result_last):
            assert orig["role"] == comp["role"]
            assert orig.get("content") == comp.get("content")

    def test_old_tool_results_truncated(self):
        """Tool results older than truncate_after_turns get truncated."""
        from agentguard.proxy.compaction.truncator import truncate_messages

        messages = _make_messages(turns=20, tool_content_lines=50)
        config = CompactionConfig(
            enabled=True,
            recent_turns=5,
            truncate_after_turns=5,
            keep_lines=5,
        )
        result = truncate_messages(messages, config)

        # Find tool messages in the old section (not in last 5 turns)
        old_tool_msgs = [m for m in result[: -(5 * 4)] if m.get("role") == "tool"]

        for msg in old_tool_msgs:
            content = msg["content"]
            lines = content.strip().split("\n")
            # Should be truncated: 5 head + separator + 5 tail = 11 lines max
            assert len(lines) <= 12, (
                f"Expected truncated tool result (<=12 lines), got {len(lines)}"
            )

    def test_very_old_tool_results_stubbed(self):
        """Tool results older than stub_after_turns are replaced with stubs."""
        from agentguard.proxy.compaction.truncator import truncate_messages

        messages = _make_messages(turns=30, tool_content_lines=50)
        config = CompactionConfig(
            enabled=True,
            recent_turns=5,
            truncate_after_turns=5,
            stub_after_turns=15,
            keep_lines=5,
        )
        result = truncate_messages(messages, config)

        # Find the very old tool messages (turn 0-9, which are >15 turns from end)
        # These should be stubbed
        stubbed_tools = []
        for msg in result:
            if msg.get("role") == "tool" and "[compacted:" in msg.get("content", ""):
                stubbed_tools.append(msg)

        assert len(stubbed_tools) > 0, "Expected some tool results to be stubbed"
        for msg in stubbed_tools:
            # Stub should be short
            assert len(msg["content"]) < 100

    def test_all_messages_recent_no_changes(self):
        """When all messages fit within recent_turns, nothing changes."""
        from agentguard.proxy.compaction.truncator import truncate_messages

        messages = _make_messages(turns=3, tool_content_lines=10)
        config = CompactionConfig(enabled=True, recent_turns=10)
        result = truncate_messages(messages, config)

        assert len(result) == len(messages)
        for orig, comp in zip(messages, result):
            assert orig.get("content") == comp.get("content")

    def test_non_tool_messages_in_old_section_preserved(self):
        """User and assistant text messages in old section are kept."""
        from agentguard.proxy.compaction.truncator import truncate_messages

        messages = _make_messages(turns=20, tool_content_lines=50)
        config = CompactionConfig(enabled=True, recent_turns=5)
        result = truncate_messages(messages, config)

        # Count user messages in old section
        old_users = [m for m in result[: -(5 * 4)] if m.get("role") == "user"]
        # Should still have user messages (they're text, not tool output)
        assert len(old_users) > 0

    def test_tool_call_messages_preserved(self):
        """Assistant messages with tool_calls are kept (only the result is truncated)."""
        from agentguard.proxy.compaction.truncator import truncate_messages

        messages = _make_messages(turns=20, tool_content_lines=50)
        config = CompactionConfig(enabled=True, recent_turns=5)
        result = truncate_messages(messages, config)

        # tool_calls messages should still exist
        tool_call_msgs = [m for m in result if m.get("tool_calls") is not None]
        assert len(tool_call_msgs) == 20  # All 20 turns had tool calls

    def test_truncation_marker_in_content(self):
        """Truncated tool results contain a visible marker."""
        from agentguard.proxy.compaction.truncator import truncate_messages

        messages = _make_messages(turns=20, tool_content_lines=50)
        config = CompactionConfig(
            enabled=True,
            recent_turns=5,
            truncate_after_turns=5,
            keep_lines=3,
        )
        result = truncate_messages(messages, config)

        # Find a truncated tool message in the old section
        old_tools = [
            m
            for m in result[: -(5 * 4)]
            if m.get("role") == "tool" and "[compacted:" not in m.get("content", "")
        ]

        truncated = [
            m
            for m in old_tools
            if "..." in m["content"] or "truncated" in m["content"].lower()
        ]
        assert len(truncated) > 0, "Expected truncation markers in old tool results"


class TestDeduplication:
    """Test deduplication of repeated file reads."""

    def test_repeated_file_reads_deduplicated(self):
        """Multiple reads of the same file keep only the latest."""
        from agentguard.proxy.compaction.truncator import truncate_messages

        messages = _make_file_read_messages(reads=5)
        config = CompactionConfig(
            enabled=True,
            recent_turns=10,  # All within recent, so dedup is the main effect
        )
        result = truncate_messages(messages, config)

        # Find tool results for read calls
        read_results = [
            m
            for m in result
            if m.get("role") == "tool" and "main.py" in m.get("content", "")
        ]

        # Should have at most 1 full read, others stubbed/removed
        full_reads = [
            m
            for m in read_results
            if "version 4" in m.get("content", "")  # Latest version
        ]
        assert len(full_reads) == 1, "Expected exactly one full read (the latest)"

        # Earlier reads should be stubbed
        stubbed = [
            m
            for m in read_results
            if "[compacted:" in m.get("content", "")
            or "[dedup:" in m.get("content", "")
        ]
        assert len(stubbed) >= 3, "Expected earlier reads to be stubbed/deduped"

    def test_different_files_not_deduplicated(self):
        """Reads of different files are not deduplicated."""
        from agentguard.proxy.compaction.truncator import truncate_messages

        messages = [
            {"role": "system", "content": "System."},
            {"role": "user", "content": "Read file A"},
            {
                "role": "assistant",
                "content": None,
                "tool_calls": [
                    {
                        "id": "call_a",
                        "type": "function",
                        "function": {
                            "name": "read",
                            "arguments": '{"filePath": "/a.py"}',
                        },
                    }
                ],
            },
            {"role": "tool", "tool_call_id": "call_a", "content": "content of a.py"},
            {"role": "assistant", "content": "Read a.py"},
            {"role": "user", "content": "Read file B"},
            {
                "role": "assistant",
                "content": None,
                "tool_calls": [
                    {
                        "id": "call_b",
                        "type": "function",
                        "function": {
                            "name": "read",
                            "arguments": '{"filePath": "/b.py"}',
                        },
                    }
                ],
            },
            {"role": "tool", "tool_call_id": "call_b", "content": "content of b.py"},
            {"role": "assistant", "content": "Read b.py"},
        ]

        config = CompactionConfig(enabled=True, recent_turns=10)
        result = truncate_messages(messages, config)

        # Both file contents should be present
        tool_contents = [m["content"] for m in result if m.get("role") == "tool"]
        assert any("a.py" in c for c in tool_contents)
        assert any("b.py" in c for c in tool_contents)


class TestTurnCounting:
    """Test turn boundary detection."""

    def test_turns_counted_by_user_messages(self):
        """Each user message marks a turn boundary."""
        from agentguard.proxy.compaction.truncator import count_turns

        messages = _make_messages(turns=10)
        assert count_turns(messages) == 10

    def test_system_prompt_not_counted_as_turn(self):
        """System prompt doesn't count as a turn."""
        from agentguard.proxy.compaction.truncator import count_turns

        messages = [{"role": "system", "content": "System."}]
        assert count_turns(messages) == 0

    def test_consecutive_user_messages_each_count(self):
        """Multiple user messages without responses each count as a turn."""
        from agentguard.proxy.compaction.truncator import count_turns

        messages = [
            {"role": "system", "content": "System."},
            {"role": "user", "content": "First"},
            {"role": "user", "content": "Second"},
            {"role": "user", "content": "Third"},
        ]
        assert count_turns(messages) == 3


class TestTokenEstimation:
    """Test token count estimation for messages."""

    def test_estimate_messages_tokens(self):
        """Token estimation returns reasonable counts."""
        from agentguard.proxy.compaction.truncator import estimate_messages_tokens

        messages = _make_messages(turns=10, tool_content_lines=50)
        tokens = estimate_messages_tokens(messages)

        # 10 turns x 50 lines per tool result = significant tokens
        assert tokens > 1000, f"Expected >1000 tokens, got {tokens}"

    def test_empty_messages_zero_tokens(self):
        """Empty message list has zero tokens."""
        from agentguard.proxy.compaction.truncator import estimate_messages_tokens

        assert estimate_messages_tokens([]) == 0

    def test_truncation_reduces_tokens(self):
        """Truncated messages have fewer tokens than originals."""
        from agentguard.proxy.compaction.truncator import (
            estimate_messages_tokens,
            truncate_messages,
        )

        messages = _make_messages(turns=20, tool_content_lines=100)
        config = CompactionConfig(
            enabled=True,
            recent_turns=5,
            truncate_after_turns=5,
            stub_after_turns=15,
            keep_lines=3,
        )

        before = estimate_messages_tokens(messages)
        result = truncate_messages(messages, config)
        after = estimate_messages_tokens(result)

        assert after < before, f"Expected reduction: before={before}, after={after}"
        # Should achieve significant reduction
        ratio = after / before
        assert ratio < 0.7, f"Expected >30% reduction, got {1 - ratio:.1%}"
