"""Tests for structured logging and diagnostics in the compaction module.

Covers:
- Ollama → inference server rename (_call_inference_server exists)
- Structured logging on summarization success and fallback
- CompactionResult.summarizer_success field (True, False, None)
- CompactionConfig.log_dir field (CLI-only, no env var fallback, no hardcoded paths)
- FileHandler wired to log_dir when set
- summarize_segment returns (summary, used_fallback) tuple
- --compaction-log-dir CLI argument (renamed from --log-dir)
- Audit metadata includes compaction_summarizer_success
"""

from __future__ import annotations

import logging
import os
import tempfile
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
            result, used_fallback = await summarize_segment(messages, config)

        assert result == "Summary of conversation."
        assert used_fallback is False

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
            result, used_fallback = await summarize_segment(messages, config)

        # Should still return a fallback (not raise)
        assert isinstance(result, str)
        assert len(result) > 0
        assert used_fallback is True

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


class TestSummarizeSegmentReturnType:
    """Verify summarize_segment returns (summary, used_fallback) tuple."""

    @pytest.mark.asyncio
    async def test_returns_tuple_on_success(self):
        """summarize_segment returns (str, False) on LLM success."""
        from agentguard.proxy.compaction.summarizer import summarize_segment

        config = CompactionConfig(enabled=True)
        messages = _make_messages(3)

        with patch(
            "agentguard.proxy.compaction.summarizer._call_inference_server",
            new_callable=AsyncMock,
            return_value="A concise summary.",
        ):
            result = await summarize_segment(messages, config)

        assert isinstance(result, tuple)
        assert len(result) == 2
        summary, used_fallback = result
        assert summary == "A concise summary."
        assert used_fallback is False

    @pytest.mark.asyncio
    async def test_returns_tuple_on_fallback(self):
        """summarize_segment returns (str, True) on fallback."""
        from agentguard.proxy.compaction.summarizer import summarize_segment

        config = CompactionConfig(enabled=True)
        messages = _make_messages(3)

        with patch(
            "agentguard.proxy.compaction.summarizer._call_inference_server",
            new_callable=AsyncMock,
            side_effect=TimeoutError("Server timed out"),
        ):
            result = await summarize_segment(messages, config)

        assert isinstance(result, tuple)
        summary, used_fallback = result
        assert isinstance(summary, str)
        assert len(summary) > 0
        assert used_fallback is True

    @pytest.mark.asyncio
    async def test_returns_empty_for_empty_messages(self):
        """summarize_segment returns ('', False) for empty input."""
        from agentguard.proxy.compaction.summarizer import summarize_segment

        config = CompactionConfig(enabled=True)
        result = await summarize_segment([], config)

        assert isinstance(result, tuple)
        summary, used_fallback = result
        assert summary == ""
        assert used_fallback is False


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
            return_value=("Summary of earlier conversation.", False),
        ):
            result = await engine.compact(messages)

        assert result.phase_used == "summarization"
        assert result.summarizer_success is True

    @pytest.mark.asyncio
    async def test_engine_sets_summarizer_success_false_on_fallback(self):
        """Engine sets summarizer_success=False when fallback was used."""
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
            return_value=(
                "[Previous conversation history: 40 messages, 20 user, 20 assistant]",
                True,
            ),
        ):
            result = await engine.compact(messages)

        assert result.phase_used == "summarization"
        assert result.summarizer_success is False

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
    """Verify log_dir is CLI-only, no env var fallback, no hardcoded paths."""

    def test_log_dir_default_is_empty_string(self):
        """CompactionConfig log_dir defaults to empty string (no logging)."""
        config = CompactionConfig()
        assert config.log_dir == ""

    def test_log_dir_default_ignores_env_var(self):
        """CompactionConfig does NOT read AGENTGUARD_LOG_DIR env var."""
        with patch.dict(os.environ, {"AGENTGUARD_LOG_DIR": "/tmp/ag-logs/"}):
            config = CompactionConfig()
            assert config.log_dir == "", (
                "log_dir should not read AGENTGUARD_LOG_DIR; it should be CLI-only"
            )

    def test_compaction_log_dir_default_function_removed(self):
        """compaction_log_dir_default() helper no longer exists in config module."""
        import agentguard.proxy.compaction.config as config_mod

        assert not hasattr(config_mod, "compaction_log_dir_default"), (
            "compaction_log_dir_default should be removed; log_dir is CLI-only"
        )

    def test_no_env_var_reference_in_config_source(self):
        """config.py must NOT reference AGENTGUARD_LOG_DIR env variable."""
        import inspect

        from agentguard.proxy.compaction import config as config_mod

        source = inspect.getsource(config_mod)
        assert "AGENTGUARD_LOG_DIR" not in source, (
            "AGENTGUARD_LOG_DIR env var reference found in config.py; "
            "log_dir should be purely CLI-driven"
        )

    def test_no_env_var_reference_in_cli_help(self):
        """CLI help text for --compaction-log-dir must NOT mention AGENTGUARD_LOG_DIR."""
        import inspect

        from agentguard import cli as cli_mod

        source = inspect.getsource(cli_mod)
        assert "AGENTGUARD_LOG_DIR" not in source, (
            "AGENTGUARD_LOG_DIR reference found in cli.py; "
            "help text should not mention the env var"
        )

    def test_log_dir_custom(self):
        """CompactionConfig accepts a custom log_dir."""
        config = CompactionConfig(log_dir="/tmp/test-logs/")
        assert config.log_dir == "/tmp/test-logs/"

    def test_no_hardcoded_nas_path_in_config(self):
        """CompactionConfig must NOT contain hardcoded NAS/infrastructure paths."""
        import inspect

        from agentguard.proxy.compaction import config as config_mod

        source = inspect.getsource(config_mod)
        assert "/mnt/" not in source, "Hardcoded /mnt/ path found in config.py"
        assert "nas" not in source.lower(), "Hardcoded NAS path found in config.py"

    def test_no_hardcoded_nas_path_in_cli(self):
        """CLI must NOT contain hardcoded NAS/infrastructure paths."""
        import inspect

        from agentguard import cli as cli_mod

        source = inspect.getsource(cli_mod)
        assert "/mnt/" not in source, "Hardcoded /mnt/ path found in cli.py"

    def test_config_no_os_import(self):
        """config.py should not import os (no longer needed without env var)."""
        import inspect

        from agentguard.proxy.compaction import config as config_mod

        source = inspect.getsource(config_mod)
        # os is still needed for configure_compaction_logging (makedirs, path.join)
        # but should NOT appear in the module-level default_factory
        assert "os.environ" not in source, (
            "os.environ reference found in config.py; env var fallback should be removed"
        )

    def test_no_internal_model_name_in_defaults(self):
        """Defaults must not reference internal/custom model names."""
        config = CompactionConfig()
        assert "rnj-" not in config.summarizer_model, (
            f"Internal model name '{config.summarizer_model}' leaked into defaults"
        )

    def test_no_internal_model_name_in_cli(self):
        """CLI defaults must not reference internal/custom model names."""
        import inspect

        from agentguard import cli as cli_mod

        source = inspect.getsource(cli_mod)
        assert "rnj-1" not in source, (
            "Internal model name 'rnj-1' leaked into CLI defaults/help text"
        )

    def test_no_internal_model_name_in_config_source(self):
        """config.py source must not reference internal/custom model names."""
        import inspect

        from agentguard.proxy.compaction import config as config_mod

        source = inspect.getsource(config_mod)
        assert "rnj-" not in source, "Internal model name leaked into config.py source"


class TestFileHandlerWiring:
    """Verify log_dir configures a FileHandler when set."""

    def test_configure_compaction_logging_creates_handler(self):
        """configure_compaction_logging adds FileHandler when log_dir is set."""
        from agentguard.proxy.compaction.config import configure_compaction_logging

        with tempfile.TemporaryDirectory() as tmpdir:
            config = CompactionConfig(log_dir=tmpdir)
            handler = configure_compaction_logging(config)

            assert handler is not None
            assert isinstance(handler, logging.FileHandler)

            # Verify the file was created in the right directory
            assert tmpdir in handler.baseFilename

            # Clean up
            handler.close()
            # Remove handler from the logger
            log = logging.getLogger("agentguard.proxy.compaction")
            log.removeHandler(handler)

    def test_configure_compaction_logging_sets_logger_level(self):
        """configure_compaction_logging sets logger level to DEBUG.

        Without this, the root logger's WARNING level blocks INFO messages
        from the summarizer success path (logger.info in summarizer.py).
        """
        from agentguard.proxy.compaction.config import configure_compaction_logging

        with tempfile.TemporaryDirectory() as tmpdir:
            config = CompactionConfig(log_dir=tmpdir)
            handler = configure_compaction_logging(config)
            assert handler is not None

            log = logging.getLogger("agentguard.proxy.compaction")
            assert log.level <= logging.DEBUG, (
                f"Logger level is {logging.getLevelName(log.level)}, "
                f"expected DEBUG or lower so INFO messages reach the handler"
            )

            # Also verify INFO messages actually pass through
            assert log.isEnabledFor(logging.INFO), (
                "Logger should allow INFO messages for summarizer success logging"
            )

            # Clean up
            handler.close()
            log.removeHandler(handler)
            log.setLevel(logging.NOTSET)

    def test_info_messages_reach_file_handler(self):
        """INFO-level messages from child loggers must reach the compaction log file.

        This is the exact scenario: summarizer.py uses logger.info() for
        success messages, which must pass through to the file handler.
        """
        from agentguard.proxy.compaction.config import configure_compaction_logging

        with tempfile.TemporaryDirectory() as tmpdir:
            config = CompactionConfig(log_dir=tmpdir)
            handler = configure_compaction_logging(config)
            assert handler is not None

            # Simulate what summarizer.py does
            child_logger = logging.getLogger("agentguard.proxy.compaction.summarizer")
            child_logger.info("summarization_success model=test duration_ms=100")

            handler.flush()

            log_path = os.path.join(tmpdir, "compaction.log")
            content = open(log_path).read()
            assert "summarization_success" in content, (
                f"INFO message not found in compaction.log. Content: {content!r}"
            )

            # Clean up
            handler.close()
            parent_log = logging.getLogger("agentguard.proxy.compaction")
            parent_log.removeHandler(handler)
            parent_log.setLevel(logging.NOTSET)

    def test_configure_compaction_logging_noop_when_empty(self):
        """configure_compaction_logging returns None when log_dir is empty."""
        from agentguard.proxy.compaction.config import configure_compaction_logging

        config = CompactionConfig(log_dir="")
        handler = configure_compaction_logging(config)
        assert handler is None


class TestCompactionLogDirCLI:
    """Verify --compaction-log-dir CLI argument (renamed from --log-dir)."""

    def test_compaction_log_dir_argument_exists(self):
        """CLI has --compaction-log-dir argument."""
        from agentguard.cli import _build_parser

        parser = _build_parser()
        # Parse with proxy subcommand
        args = parser.parse_args(
            ["proxy", "https://api.example.com", "--compaction-log-dir", "/tmp/logs/"]
        )
        assert args.compaction_log_dir == "/tmp/logs/"

    def test_log_dir_argument_does_not_exist(self):
        """CLI no longer has --log-dir argument (renamed to --compaction-log-dir)."""
        from agentguard.cli import _build_parser

        parser = _build_parser()
        with pytest.raises(SystemExit):
            parser.parse_args(
                ["proxy", "https://api.example.com", "--log-dir", "/tmp/logs/"]
            )

    def test_compaction_log_dir_default_is_empty(self):
        """--compaction-log-dir defaults to empty string."""
        from agentguard.cli import _build_parser

        parser = _build_parser()
        args = parser.parse_args(["proxy", "https://api.example.com"])
        assert args.compaction_log_dir == ""

    def test_build_compaction_config_uses_compaction_log_dir(self):
        """_build_compaction_config reads compaction_log_dir from args."""
        from agentguard.cli import _build_compaction_config, _build_parser

        parser = _build_parser()
        args = parser.parse_args(
            [
                "proxy",
                "https://api.example.com",
                "--compaction",
                "--compaction-log-dir",
                "/tmp/my-logs/",
            ]
        )
        config = _build_compaction_config(args)
        assert config is not None
        assert config.log_dir == "/tmp/my-logs/"


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
            return_value=("Summary.", False),
        ):
            _compacted_body, metrics = await mw._compact_request_body(body)

        assert "summarizer_success" in metrics


class TestCompactionLoggingWiring:
    """Verify configure_compaction_logging is called from production code paths."""

    def test_cmd_proxy_calls_configure_compaction_logging(self):
        """_cmd_proxy must call configure_compaction_logging after building config."""
        import ast
        import inspect

        from agentguard.cli import _cmd_proxy

        source = inspect.getsource(_cmd_proxy)
        tree = ast.parse(source)

        # Walk the AST looking for a call to configure_compaction_logging
        found = False
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func = node.func
                # Match both `configure_compaction_logging(...)` and
                # `module.configure_compaction_logging(...)`
                if (
                    isinstance(func, ast.Name)
                    and func.id == "configure_compaction_logging"
                ):
                    found = True
                    break
                if (
                    isinstance(func, ast.Attribute)
                    and func.attr == "configure_compaction_logging"
                ):
                    found = True
                    break

        assert found, (
            "configure_compaction_logging() is not called in _cmd_proxy(). "
            "File logging will never activate at runtime even when "
            "--compaction-log-dir is set."
        )
