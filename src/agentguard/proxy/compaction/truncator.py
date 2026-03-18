"""Phase 1: Rule-based context truncation.

Deterministic, no-LLM compaction of conversation messages.
Truncates old tool outputs and deduplicates repeated file reads
to reduce token usage before forwarding to the upstream LLM.
"""

from __future__ import annotations

import copy
import json
import logging
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from agentguard.proxy.compaction.config import CompactionConfig

logger = logging.getLogger(__name__)


def count_turns(messages: list[dict[str, Any]]) -> int:
    """Count the number of turns in a message array.

    A turn is defined by a user message. System messages are not
    counted.

    Args:
        messages: OpenAI-format message array.

    Returns:
        Number of user-message turns.
    """
    return sum(1 for m in messages if m.get("role") == "user")


def estimate_messages_tokens(messages: list[dict[str, Any]]) -> int:
    """Estimate total tokens across all messages.

    Uses a simple heuristic: ~4 characters per token.

    Args:
        messages: OpenAI-format message array.

    Returns:
        Estimated token count.
    """
    total_chars = 0
    for msg in messages:
        content = msg.get("content")
        if isinstance(content, str):
            total_chars += len(content)
        elif isinstance(content, list):
            for block in content:
                if isinstance(block, dict):
                    text = block.get("text", "")
                    if isinstance(text, str):
                        total_chars += len(text)
        # Count tool_calls arguments too
        tool_calls = msg.get("tool_calls")
        if isinstance(tool_calls, list):
            for tc in tool_calls:
                if isinstance(tc, dict):
                    fn = tc.get("function", {})
                    if isinstance(fn, dict):
                        args = fn.get("arguments", "")
                        if isinstance(args, str):
                            total_chars += len(args)
    return max(0, total_chars // 4)


def truncate_messages(
    messages: list[dict[str, Any]],
    config: CompactionConfig,
) -> list[dict[str, Any]]:
    """Truncate old tool results in a conversation.

    Applies three strategies based on message age:
    1. Recent messages (last N turns): kept verbatim
    2. Old messages (truncate_after_turns < age <= stub_after_turns):
       tool results truncated to first+last keep_lines
    3. Very old messages (age > stub_after_turns): tool results
       replaced with a one-line stub

    Additionally, deduplicates repeated file reads (same file path),
    keeping only the most recent read.

    Args:
        messages: OpenAI-format message array.
        config: Compaction configuration.

    Returns:
        New message array with truncated/stubbed tool results.
        Original messages are not modified.
    """
    if not messages:
        return []

    # Deep copy to avoid mutating originals
    result = copy.deepcopy(messages)

    # Identify turn boundaries (indices of user messages)
    turn_indices = [i for i, m in enumerate(result) if m.get("role") == "user"]
    total_turns = len(turn_indices)

    if total_turns == 0:
        return result

    # Determine the index where "recent" section starts
    recent_start_turn = max(0, total_turns - config.recent_turns)
    if recent_start_turn < total_turns:
        recent_start_idx = turn_indices[recent_start_turn]
    else:
        recent_start_idx = len(result)

    # Determine the index where "truncate" section starts (vs stub)
    truncate_start_turn = max(0, total_turns - config.stub_after_turns)
    if truncate_start_turn < total_turns:
        truncate_start_idx = turn_indices[truncate_start_turn]
    else:
        truncate_start_idx = 0

    # Build a map of tool_call_id -> tool_call info for deduplication
    # Track which file paths have been read, and find the latest read
    file_read_latest: dict[str, int] = {}  # filepath -> index of latest tool result
    _find_file_reads(result, file_read_latest)

    # Process messages
    stub_count = 0
    truncate_count = 0
    dedup_count = 0
    for i, msg in enumerate(result):
        if i >= recent_start_idx:
            # Recent section — skip unless dedup applies
            if msg.get("role") == "tool" and not _is_latest_read(
                i, msg, result, file_read_latest
            ):
                _stub_dedup(msg, result)
                dedup_count += 1
            continue

        if msg.get("role") != "tool":
            continue

        # Check deduplication first
        if not _is_latest_read(i, msg, result, file_read_latest):
            _stub_dedup(msg, result)
            dedup_count += 1
            continue

        content = msg.get("content", "")
        if not isinstance(content, str):
            continue

        if i < truncate_start_idx:
            # Very old — stub it
            tool_name = _get_tool_name(msg, result)
            msg["content"] = f"[compacted: ran {tool_name}]"
            stub_count += 1
        else:
            # Old but not ancient — truncate
            _truncate_content(msg, config.keep_lines)
            truncate_count += 1

    logger.debug(
        "truncation_stats messages=%d stubs=%d truncated=%d "
        "deduplicated=%d recent_start=%d",
        len(result),
        stub_count,
        truncate_count,
        dedup_count,
        recent_start_idx,
    )

    return result


def _find_file_reads(
    messages: list[dict[str, Any]],
    file_read_latest: dict[str, int],
) -> None:
    """Find all file read tool results and record the latest index for each path.

    Scans for tool results where the preceding assistant tool_call
    used a function named "read" (or similar file-reading tools).
    """
    for i, msg in enumerate(messages):
        if msg.get("role") != "tool":
            continue

        tool_call_id = msg.get("tool_call_id")
        if not tool_call_id:
            continue

        # Find the matching tool_call
        file_path = _get_file_path_for_read(tool_call_id, messages)
        if file_path is not None:
            file_read_latest[file_path] = i


def _get_file_path_for_read(
    tool_call_id: str,
    messages: list[dict[str, Any]],
) -> str | None:
    """Extract file path from a read tool call by its ID.

    Returns the file path if the tool call is a file read, None otherwise.
    """
    for msg in messages:
        tool_calls = msg.get("tool_calls")
        if not isinstance(tool_calls, list):
            continue
        for tc in tool_calls:
            if not isinstance(tc, dict):
                continue
            if tc.get("id") != tool_call_id:
                continue
            fn = tc.get("function", {})
            if not isinstance(fn, dict):
                continue
            name = fn.get("name", "")
            # Match common file reading tool names
            if name in ("read", "file_read", "agentguard_file_read", "Read"):
                args_str = fn.get("arguments", "")
                try:
                    args = (
                        json.loads(args_str) if isinstance(args_str, str) else args_str
                    )
                except (json.JSONDecodeError, TypeError):
                    return None
                if isinstance(args, dict):
                    return args.get("filePath") or args.get("path") or args.get("file")
    return None


def _is_latest_read(
    idx: int,
    msg: dict[str, Any],
    messages: list[dict[str, Any]],
    file_read_latest: dict[str, int],
) -> bool:
    """Check if this tool result is the latest read of its file.

    Returns True if this is not a file read, or if it's the latest one.
    """
    tool_call_id = msg.get("tool_call_id")
    if not tool_call_id:
        return True

    file_path = _get_file_path_for_read(tool_call_id, messages)
    if file_path is None:
        return True  # Not a file read

    return file_read_latest.get(file_path) == idx


def _stub_dedup(msg: dict[str, Any], messages: list[dict[str, Any]]) -> None:
    """Replace a deduplicated tool result with a stub."""
    tool_call_id = msg.get("tool_call_id", "")
    file_path = _get_file_path_for_read(tool_call_id, messages)
    if file_path:
        msg["content"] = f"[dedup: previously read {file_path}]"
    else:
        tool_name = _get_tool_name(msg, messages)
        msg["content"] = f"[dedup: duplicate {tool_name} call]"


def _get_tool_name(
    msg: dict[str, Any],
    messages: list[dict[str, Any]],
) -> str:
    """Get the tool function name for a tool result message."""
    tool_call_id = msg.get("tool_call_id", "")
    for m in messages:
        tool_calls = m.get("tool_calls")
        if not isinstance(tool_calls, list):
            continue
        for tc in tool_calls:
            if isinstance(tc, dict) and tc.get("id") == tool_call_id:
                fn = tc.get("function", {})
                if isinstance(fn, dict):
                    return str(fn.get("name", "unknown_tool"))
    return "unknown_tool"


def _truncate_content(msg: dict[str, Any], keep_lines: int) -> None:
    """Truncate a tool result's content to first+last N lines."""
    content = msg.get("content", "")
    if not isinstance(content, str):
        return

    lines = content.split("\n")
    if len(lines) <= keep_lines * 2 + 1:
        return  # Already short enough

    head = lines[:keep_lines]
    tail = lines[-keep_lines:]
    omitted = len(lines) - keep_lines * 2
    separator = f"... [{omitted} lines truncated] ..."

    msg["content"] = "\n".join([*head, separator, *tail])
