"""Tests for structured logging and diagnostics in the compaction module.

Covers:
- Ollama → inference server rename (_call_inference_server exists)
- Structured logging on summarization success and fallback
- CompactionResult.summarizer_success field
- CompactionConfig.log_dir field
- Audit metadata includes compaction_summarizer_success
"""

from __future__ import annotations

import logging
from unittest.mock import AsyncMock, patch

import pytest

from agentguard.proxy.compaction.config import CompactionConfig


def _make_messages(count: int = 5) -> list[dict]:
    """Build conversation messages for testing."""
    messages = []
    for i in range(count):
        messages.append({"role": "user", "content": f"Question {i}"})
        messages.append({"role": "assistant", "content": f"Answer {i}"})
    return messages


class TestOllamaRename:
    """Verify _call_ollama has been renamed to _call_inference_server."""

    def test_call_inference_server_exists(self):
        """_call_inference_server can be imported from summarizer."""
        from agentguard.proxy.compaction.summarizer import (
            _call_inference_server,  # noqa: F401
        )

    def test_call_ollama_does_not_exist(self):
        """_call_ollama no longer exists in summarizer module."""
        import agentguard.proxy.compaction.summarizer as mod

        assert not hasattr(mod, "_call_ollama"), (
            "_call_ollama should be renamed to _call_inference_server"
        )


class TestSummarizerLogging:
    """Verify structured logging is emitted by the summarizer."""

    @pytest.mark.asyncio
    async def test_logs_on_successful_summarization(self, caplog):
        """summarize_segment logs an INFO message on success."""
        from agentguard.proxy.compaction.summarizer import summarize_segment

        config = CompactionConfig(enabled=True)
        messages = _make_messages(3)

        with (
            patch(
                "agentguard.proxy.compaction.summarizer._call_inference_server",
                new_callable=AsyncMock,
                return_value="Summary of conversation.",
            ),
            caplog.at_level(
                logging.INFO, logger="agentguard.proxy.compaction.summarizer"
            ),
        ):
            await summarize_segment(messages, config)

        # Should have at least one INFO log about success
        info_records = [
            r
            for r in caplog.records
            if r.levelno == logging.INFO
            and "agentguard.proxy.compaction.summarizer" in r.name
        ]
        assert len(info_records) >= 1, (
            f"Expected INFO log on summarization success, got: {caplog.text}"
        )
        # Log should mention success/model
        log_text = " ".join(r.getMessage() for r in info_records)
        assert "success" in log_text.lower() or "summar" in log_text.lower()

    @pytest.mark.asyncio
    async def test_logs_warning_on_fallback(self, caplog):
        """summarize_segment logs a WARNING when falling back."""
        from agentguard.proxy.compaction.summarizer import summarize_segment

        config = CompactionConfig(enabled=True)
        messages = _make_messages(3)

        with (
            patch(
                "agentguard.proxy.compaction.summarizer._call_inference_server",
                new_callable=AsyncMock,
                side_effect=ConnectionError("Connection refused"),
            ),
            caplog.at_level(
                logging.WARNING, logger="agentguard.proxy.compaction.summarizer"
            ),
        ):
            result = await summarize_segment(messages, config)

        # Should still return a fallback (not raise)
        assert isinstance(result, str)
        assert len(result) > 0

        # Should have a WARNING log
        warn_records = [
            r
            for r in caplog.records
            if r.levelno == logging.WARNING
            and "agentguard.proxy.compaction.summarizer" in r.name
        ]
        assert len(warn_records) >= 1, (
            f"Expected WARNING log on fallback, got: {caplog.text}"
        )
        # Warning should mention the error
        warn_text = " ".join(r.getMessage() for r in warn_records)
        assert "connection" in warn_text.lower() or "fallback" in warn_text.lower()


class TestSummarizerSuccess:
    """Verify CompactionResult exposes summarizer_success field."""

    def test_compaction_result_has_summarizer_success(self):
        """CompactionResult has a summarizer_success attribute."""
        from agentguard.proxy.compaction.engine import CompactionResult

        # Check the field exists in the dataclass
        result = CompactionResult(
            messages=[],
            tokens_before=1000,
            tokens_after=500,
            messages_before=10,
            messages_after=5,
            phase_used="summarization",
            summarizer_success=True,
        )
        assert result.summarizer_success is True

    def test_summarizer_success_none_when_not_summarized(self):
        """summarizer_success is None when summarization wasn't used."""
        from agentguard.proxy.compaction.engine import CompactionResult

        result = CompactionResult(
            messages=[],
            tokens_before=1000,
            tokens_after=1000,
            messages_before=10,
            messages_after=10,
            phase_used="none",
            summarizer_success=None,
        )
        assert result.summarizer_success is None

    @pytest.mark.asyncio
    async def test_engine_sets_summarizer_success_true_on_llm_success(self):
        """Engine sets summarizer_success=True when LLM summarization works."""
        from agentguard.proxy.compaction.engine import CompactionEngine

        config = CompactionConfig(
            enabled=True,
            token_budget=500,
            recent_turns=2,
            truncate_after_turns=2,
            stub_after_turns=5,
            keep_lines=1,
        )
        engine = CompactionEngine(config)

        # Build enough messages to trigger Phase 2
        messages = [{"role": "system", "content": "You are an assistant."}]
        for i in range(20):
            messages.append({"role": "user", "content": f"User message {i} " * 50})
            messages.append({"role": "assistant", "content": f"Response {i} " * 50})

        with patch(
            "agentguard.proxy.compaction.engine.summarize_segment",
            new_callable=AsyncMock,
            return_value="Summary of earlier conversation.",
        ):
            result = await engine.compact(messages)

        assert result.phase_used == "summarization"
        assert result.summarizer_success is True

    @pytest.mark.asyncio
    async def test_engine_sets_summarizer_success_none_under_budget(self):
        """Engine sets summarizer_success=None when under budget."""
        from agentguard.proxy.compaction.engine import CompactionEngine

        config = CompactionConfig(
            enabled=True,
            token_budget=100_000,
            recent_turns=50,
        )
        engine = CompactionEngine(config)
        messages = _make_messages(3)

        result = await engine.compact(messages)

        assert result.phase_used == "none"
        assert result.summarizer_success is None


class TestLogDirConfig:
    """Verify log_dir is configurable on CompactionConfig."""

    def test_log_dir_default(self):
        """CompactionConfig has a default log_dir."""
        config = CompactionConfig()
        assert config.log_dir == "/mnt/nas/rsn/roboter-schlafen-nicht/output/"

    def test_log_dir_custom(self):
        """CompactionConfig accepts a custom log_dir."""
        config = CompactionConfig(log_dir="/tmp/test-logs/")
        assert config.log_dir == "/tmp/test-logs/"


class TestEngineLogging:
    """Verify structured logging in the compaction engine."""

    @pytest.mark.asyncio
    async def test_engine_logs_phase_decision(self, caplog):
        """Engine logs which phase it used."""
        from agentguard.proxy.compaction.engine import CompactionEngine

        config = CompactionConfig(
            enabled=True,
            token_budget=100_000,
            recent_turns=50,
        )
        engine = CompactionEngine(config)
        messages = _make_messages(3)

        with caplog.at_level(
            logging.DEBUG, logger="agentguard.proxy.compaction.engine"
        ):
            await engine.compact(messages)

        # Should have logged something about the phase
        assert len(caplog.records) >= 1, (
            f"Expected at least 1 log from engine, got: {caplog.text}"
        )


class TestMiddlewareAuditMetadata:
    """Verify middleware passes summarizer_success into audit metadata."""

    @pytest.mark.asyncio
    async def test_compaction_metrics_include_summarizer_success(self):
        """_compact_request_body returns summarizer_success in metrics."""
        import json

        from agentguard.proxy.config import ProxyConfig
        from agentguard.proxy.middleware import GuardMiddleware

        config = ProxyConfig(
            upstream_base_url="https://api.example.com",
            compaction=CompactionConfig(
                enabled=True,
                token_budget=500,
                recent_turns=2,
                truncate_after_turns=2,
                stub_after_turns=5,
                keep_lines=1,
            ),
        )
        mw = GuardMiddleware(config)

        # Build a body with enough messages to trigger Phase 2
        msgs = [{"role": "system", "content": "You are an assistant."}]
        for i in range(20):
            msgs.append({"role": "user", "content": f"User message {i} " * 50})
            msgs.append({"role": "assistant", "content": f"Response {i} " * 50})

        body = json.dumps({"model": "test", "messages": msgs}).encode()

        with patch(
            "agentguard.proxy.compaction.engine.summarize_segment",
            new_callable=AsyncMock,
            return_value="Summary.",
        ):
            _compacted_body, metrics = await mw._compact_request_body(body)

        assert "summarizer_success" in metrics
