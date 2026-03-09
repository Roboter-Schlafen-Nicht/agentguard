"""Tests for the ``python -m agentguard.proxy`` entry point."""

from __future__ import annotations

import builtins
from typing import TYPE_CHECKING
from unittest.mock import MagicMock, patch

import pytest

if TYPE_CHECKING:
    from pathlib import Path

from agentguard.proxy.__main__ import main


class TestProxyMainEntryPoint:
    """Test the __main__.py main() function."""

    def test_missing_uvicorn_shows_install_message(self) -> None:
        """When uvicorn is not installed, should print install hint."""
        original_import = builtins.__import__

        def mock_import(name, *args, **kwargs):
            if name == "uvicorn":
                raise ImportError("No module named 'uvicorn'")
            return original_import(name, *args, **kwargs)

        with patch("builtins.__import__", side_effect=mock_import):
            result = main()

        assert result == 1

    def test_missing_upstream_argument_exits(self) -> None:
        """Calling main without upstream URL should exit with error."""
        with patch("sys.argv", ["agentguard-proxy"]):
            with pytest.raises(SystemExit) as exc_info:
                main()
            assert exc_info.value.code != 0

    def test_valid_upstream_calls_uvicorn(self) -> None:
        """Valid arguments should call uvicorn.run with correct params."""
        with (
            patch(
                "sys.argv",
                [
                    "agentguard-proxy",
                    "https://api.openai.com",
                    "--host",
                    "0.0.0.0",
                    "--port",
                    "9090",
                ],
            ),
            patch("uvicorn.run") as mock_run,
        ):
            result = main()

        assert result == 0
        mock_run.assert_called_once()
        call_args = mock_run.call_args
        assert call_args[1]["host"] == "0.0.0.0"
        assert call_args[1]["port"] == 9090

    def test_all_options_passed_to_config(self, tmp_path: Path) -> None:
        """All CLI options should be reflected in the created config."""
        policy_dir = tmp_path / "policies"
        policy_dir.mkdir()
        audit_dir = tmp_path / "audit"
        audit_dir.mkdir()

        with (
            patch(
                "sys.argv",
                [
                    "agentguard-proxy",
                    "https://api.anthropic.com",
                    "--host",
                    "0.0.0.0",
                    "--port",
                    "7777",
                    "--builtins",
                    "--auto-discover",
                    "--policy-dir",
                    str(policy_dir),
                    "--audit-dir",
                    str(audit_dir),
                    "--actor",
                    "test-agent",
                    "--scan-responses",
                    "--timeout",
                    "30",
                ],
            ),
            patch("uvicorn.run"),
            patch("agentguard.proxy.app.create_app") as mock_create,
        ):
            mock_create.return_value = MagicMock()
            result = main()

        assert result == 0
        # Verify create_app was called with correct config
        config = mock_create.call_args[0][0]
        assert config.upstream_base_url == "https://api.anthropic.com"
        assert config.host == "0.0.0.0"
        assert config.port == 7777
        assert config.load_builtins is True
        assert config.auto_discover is True
        assert config.policy_dir == str(policy_dir)
        assert config.audit_dir == str(audit_dir)
        assert config.actor == "test-agent"
        assert config.scan_responses is True
        assert config.timeout == 30.0

    def test_default_options(self) -> None:
        """Default options should use sensible defaults."""
        with (
            patch("sys.argv", ["agentguard-proxy", "https://api.openai.com"]),
            patch("uvicorn.run"),
            patch("agentguard.proxy.app.create_app") as mock_create,
        ):
            mock_create.return_value = MagicMock()
            result = main()

        assert result == 0
        config = mock_create.call_args[0][0]
        assert config.host == "127.0.0.1"
        assert config.port == 8080
        assert config.load_builtins is False
        assert config.auto_discover is False
        assert config.policy_dir is None
        assert config.audit_dir is None
        assert config.actor == "llm-proxy"
        assert config.scan_responses is False
        assert config.timeout == 120.0
