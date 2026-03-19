"""Compaction engine — orchestrates Phase 1 and Phase 2.

The engine first applies rule-based truncation (Phase 1). If the
result is still over the token budget, it invokes local model
summarization (Phase 2) to compress old conversation segments.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from agentguard.proxy.compaction.summarizer import summarize_segment
from agentguard.proxy.compaction.truncator import (
    estimate_messages_tokens,
    truncate_messages,
)

if TYPE_CHECKING:
    from agentguard.proxy.compaction.config import CompactionConfig

logger = logging.getLogger(__name__)


@dataclass
class CompactionResult:
    """Result of a compaction operation.

    Attributes:
        messages: The compacted message array.
        tokens_before: Estimated tokens in the original messages.
        tokens_after: Estimated tokens in the compacted messages.
        messages_before: Number of messages before compaction.
        messages_after: Number of messages after compaction.
        phase_used: Which phase was needed ("none", "truncation",
            "summarization", "hard_cap", or "disabled").
        summarizer_success: Whether the inference server returned a
            summary (True), fell back to extractive (False), or
            summarization was not attempted (None).
    """

    messages: list[dict[str, Any]]
    tokens_before: int
    tokens_after: int
    messages_before: int
    messages_after: int
    phase_used: str
    summarizer_success: bool | None = None


class CompactionEngine:
    """Orchestrates context compaction.

    Usage::

        engine = CompactionEngine(config)
        result = await engine.compact(messages)
        # result.messages is the compacted array
        # result.tokens_before / tokens_after for metrics
    """

    def __init__(self, config: CompactionConfig) -> None:
        self.config = config

    async def compact(
        self,
        messages: list[dict[str, Any]],
    ) -> CompactionResult:
        """Compact a conversation message array.

        Applies Phase 1 (truncation) first. If still over budget,
        applies Phase 2 (summarization). Returns the compacted
        messages with metrics.

        Args:
            messages: OpenAI-format message array.

        Returns:
            CompactionResult with compacted messages and metrics.
        """
        tokens_before = estimate_messages_tokens(messages)
        messages_before = len(messages)

        if not self.config.enabled:
            logger.debug(
                "compaction_disabled tokens=%d messages=%d",
                tokens_before,
                messages_before,
            )
            return CompactionResult(
                messages=messages,
                tokens_before=tokens_before,
                tokens_after=tokens_before,
                messages_before=messages_before,
                messages_after=messages_before,
                phase_used="disabled",
            )

        # Check if already under budget
        if tokens_before <= self.config.token_budget:
            logger.debug(
                "compaction_under_budget tokens=%d budget=%d",
                tokens_before,
                self.config.token_budget,
            )
            return CompactionResult(
                messages=messages,
                tokens_before=tokens_before,
                tokens_after=tokens_before,
                messages_before=messages_before,
                messages_after=messages_before,
                phase_used="none",
            )

        # Phase 1: Rule-based truncation
        truncated = truncate_messages(messages, self.config)
        tokens_after_p1 = estimate_messages_tokens(truncated)

        logger.info(
            "compaction_phase1 tokens_before=%d tokens_after=%d "
            "budget=%d messages_before=%d messages_after=%d",
            tokens_before,
            tokens_after_p1,
            self.config.token_budget,
            messages_before,
            len(truncated),
        )

        if tokens_after_p1 <= self.config.token_budget:
            return CompactionResult(
                messages=truncated,
                tokens_before=tokens_before,
                tokens_after=tokens_after_p1,
                messages_before=messages_before,
                messages_after=len(truncated),
                phase_used="truncation",
            )

        # Phase 2: Summarize old messages, keep recent ones
        compacted, summarizer_success = await self._apply_summarization(truncated)
        tokens_after_p2 = estimate_messages_tokens(compacted)

        logger.info(
            "compaction_phase2 tokens_before=%d tokens_after_p1=%d "
            "tokens_after_p2=%d budget=%d summarizer_success=%s",
            tokens_before,
            tokens_after_p1,
            tokens_after_p2,
            self.config.token_budget,
            summarizer_success,
        )

        if tokens_after_p2 <= self.config.token_budget:
            return CompactionResult(
                messages=compacted,
                tokens_before=tokens_before,
                tokens_after=tokens_after_p2,
                messages_before=messages_before,
                messages_after=len(compacted),
                phase_used="summarization",
                summarizer_success=summarizer_success,
            )

        # Phase 3: Hard cap — drop oldest non-system messages until
        # under budget. Preserves system messages and at least the
        # most recent user message.
        hard_capped = self._apply_hard_cap(compacted)
        tokens_after_p3 = estimate_messages_tokens(hard_capped)

        logger.info(
            "compaction_phase3 tokens_after_p2=%d tokens_after_p3=%d "
            "budget=%d messages_dropped=%d",
            tokens_after_p2,
            tokens_after_p3,
            self.config.token_budget,
            len(compacted) - len(hard_capped),
        )

        return CompactionResult(
            messages=hard_capped,
            tokens_before=tokens_before,
            tokens_after=tokens_after_p3,
            messages_before=messages_before,
            messages_after=len(hard_capped),
            phase_used="hard_cap",
            summarizer_success=summarizer_success,
        )

    async def _apply_summarization(
        self,
        messages: list[dict[str, Any]],
    ) -> tuple[list[dict[str, Any]], bool]:
        """Split messages into old+recent, summarize old segment.

        Args:
            messages: Already-truncated message array.

        Returns:
            Tuple of (new message array, summarizer_success).
            summarizer_success is True if the inference server returned
            a summary, False if fallback was used.
        """
        # Find turn boundaries
        turn_indices = [i for i, m in enumerate(messages) if m.get("role") == "user"]

        # Split into system + old + recent
        system_msgs = []
        if messages and messages[0].get("role") == "system":
            system_msgs = [messages[0]]
            rest = messages[1:]
            # Recalculate turn indices for rest
            turn_indices_rest = [
                i for i, m in enumerate(rest) if m.get("role") == "user"
            ]
        else:
            rest = messages
            turn_indices_rest = turn_indices

        recent_start_turn = max(0, len(turn_indices_rest) - self.config.recent_turns)
        if recent_start_turn < len(turn_indices_rest):
            recent_start_idx = turn_indices_rest[recent_start_turn]
        else:
            recent_start_idx = len(rest)

        old_msgs = rest[:recent_start_idx]
        recent_msgs = rest[recent_start_idx:]

        # Summarize old messages
        if old_msgs:
            # Compute word budget: how many words the summary can use.
            # recent_msgs + system_msgs are kept verbatim, so the summary
            # must fit in (budget - recent_tokens - system_tokens).
            # Convert tokens to words at ~0.75 words/token.
            recent_tokens = estimate_messages_tokens(recent_msgs)
            system_tokens = estimate_messages_tokens(system_msgs)
            available_tokens = max(
                200, self.config.token_budget - recent_tokens - system_tokens
            )
            max_words = int(available_tokens * 0.75)

            summary_text, used_fallback = await summarize_segment(
                old_msgs, self.config, max_words=max_words
            )
            summarizer_success = not used_fallback
            summary_msg = {
                "role": "user",
                "content": (
                    f"[Context summary of previous conversation]\n{summary_text}"
                ),
            }
            return [*system_msgs, summary_msg, *recent_msgs], summarizer_success
        else:
            return [*system_msgs, *recent_msgs], True

    def _apply_hard_cap(
        self,
        messages: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Drop oldest non-system messages until under token budget.

        Preserves all system messages and at least the most recent user
        message, even if the result still exceeds the budget.

        Args:
            messages: Message array (post Phase 1+2).

        Returns:
            Message array trimmed to fit the token budget.
        """
        budget = self.config.token_budget

        # Separate system messages from the rest
        system_msgs = [m for m in messages if m.get("role") == "system"]
        non_system = [m for m in messages if m.get("role") != "system"]

        # Find the last user message index (in non_system list)
        last_user_idx = -1
        for i in range(len(non_system) - 1, -1, -1):
            if non_system[i].get("role") == "user":
                last_user_idx = i
                break

        # Drop from the front of non_system (oldest first), skipping
        # the last user message
        while (
            estimate_messages_tokens(system_msgs + non_system) > budget
            and len(non_system) > 1
        ):
            # Don't drop the last user message
            if last_user_idx == 0:
                break
            non_system.pop(0)
            last_user_idx -= 1

        return system_msgs + non_system
