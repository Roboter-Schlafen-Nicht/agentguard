"""Compaction configuration."""

from __future__ import annotations

import logging
import os
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
        summarizer_url: Inference server API base URL (Ollama-compatible).
        summarizer_model: Model name for summarization.
        summarizer_timeout: Timeout in seconds for summarization calls.
        log_dir: Directory for compaction log files.  Set via
            ``--compaction-log-dir``.  Empty string disables file logging.
    """

    enabled: bool = False
    token_budget: int = 60_000
    recent_turns: int = 10
    truncate_after_turns: int = 5
    stub_after_turns: int = 15
    keep_lines: int = 5
    summarizer_url: str = "http://localhost:11434"
    summarizer_model: str = "qwen2.5-coder:3b"
    summarizer_timeout: float = 30.0
    log_dir: str = ""


def configure_compaction_logging(
    config: CompactionConfig,
) -> logging.FileHandler | None:
    """Configure file logging for the compaction module.

    When ``config.log_dir`` is a non-empty path, creates the
    directory (if needed) and attaches a :class:`logging.FileHandler`
    to the ``agentguard.proxy.compaction`` logger hierarchy.

    Args:
        config: Compaction configuration with ``log_dir``.

    Returns:
        The FileHandler that was added, or None if file logging
        is disabled (empty ``log_dir``).
    """
    if not config.log_dir:
        return None

    log_dir = config.log_dir.rstrip("/")
    os.makedirs(log_dir, exist_ok=True)

    log_path = os.path.join(log_dir, "compaction.log")
    handler = logging.FileHandler(log_path)
    handler.setLevel(logging.DEBUG)
    formatter = logging.Formatter(
        "%(asctime)s %(name)s %(levelname)s %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )
    handler.setFormatter(formatter)

    logger = logging.getLogger("agentguard.proxy.compaction")
    logger.addHandler(handler)
    # Set the logger level to DEBUG so INFO messages from child loggers
    # (e.g. summarizer.py success path) pass through to the file handler.
    # Without this, the root logger's WARNING level blocks them.
    logger.setLevel(logging.DEBUG)

    return handler
