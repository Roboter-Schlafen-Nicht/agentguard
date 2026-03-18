"""Compaction configuration."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class CompactionConfig:
    """Configuration for context compaction.

    Attributes:
        enabled: Whether compaction is active.
        token_budget: Maximum tokens to forward to upstream.
        recent_turns: Number of recent turns to keep verbatim.
        truncate_after_turns: Truncate tool results older than this
            many turns from the end.
        stub_after_turns: Replace tool results with a one-line stub
            when older than this many turns from the end.
        keep_lines: Lines to keep at start and end of truncated
            tool results.
        summarizer_url: Ollama API base URL.
        summarizer_model: Model name for summarization.
        summarizer_timeout: Timeout in seconds for summarization calls.
    """

    enabled: bool = False
    token_budget: int = 30_000
    recent_turns: int = 10
    truncate_after_turns: int = 5
    stub_after_turns: int = 15
    keep_lines: int = 5
    summarizer_url: str = "http://localhost:11434"
    summarizer_model: str = "rnj-1:8b-16k"
    summarizer_timeout: float = 30.0
