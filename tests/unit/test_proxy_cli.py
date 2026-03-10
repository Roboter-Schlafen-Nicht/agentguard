"""Tests for the 'agentguard proxy' CLI subcommand."""

from __future__ import annotations

import io
import sys
from typing import TYPE_CHECKING
from unittest.mock import patch

if TYPE_CHECKING:
    from pathlib import Path

from agentguard.cli import main


class TestProxyCLISubcommand:
    """Test the proxy subcommand of the CLI."""

    def test_proxy_shows_in_help(self) -> None:
        """The proxy subcommand should appear in help output."""
        captured = io.StringIO()
        old_stdout = sys.stdout
        sys.stdout = captured
        try:
            main(["--help"])
        except SystemExit:
            pass
        finally:
            sys.stdout = old_stdout
        assert "proxy" in captured.getvalue()

    def test_proxy_missing_upstream_fails(self) -> None:
        """Calling proxy without upstream URL should fail."""
        captured = io.StringIO()
        old_stderr = sys.stderr
        sys.stderr = captured
        try:
            exit_code = main(["proxy"])
        except SystemExit as e:
            exit_code = e.code
        finally:
            sys.stderr = old_stderr
        assert exit_code != 0

    def test_proxy_nonexistent_policy_dir_fails(self, tmp_path: Path) -> None:
        """Proxy with nonexistent policy dir should fail."""
        captured = io.StringIO()
        old_stderr = sys.stderr
        sys.stderr = captured
        try:
            exit_code = main(
                [
                    "proxy",
                    "https://api.openai.com",
                    "--policy-dir",
                    str(tmp_path / "nonexistent"),
                ]
            )
        finally:
            sys.stderr = old_stderr
        assert exit_code == 1
        assert "not found" in captured.getvalue().lower()

    def test_proxy_calls_uvicorn_run(self) -> None:
        """Proxy should call uvicorn.run with the correct arguments."""
        with (
            patch("agentguard.cli.create_proxy_app") as mock_create,
            patch("uvicorn.run") as mock_run,
        ):
            mock_create.return_value = "fake-app"
            exit_code = main(
                [
                    "proxy",
                    "https://api.openai.com",
                    "--host",
                    "0.0.0.0",
                    "--port",
                    "9090",
                ]
            )

        assert exit_code == 0
        mock_create.assert_called_once()
        mock_run.assert_called_once()
        call_kwargs = mock_run.call_args
        assert call_kwargs[1]["host"] == "0.0.0.0"
        assert call_kwargs[1]["port"] == 9090

    def test_proxy_passes_all_options(self, tmp_path: Path) -> None:
        """All CLI options should be passed to ProxyConfig."""
        policy_dir = tmp_path / "policies"
        policy_dir.mkdir()
        audit_dir = tmp_path / "audit"
        audit_dir.mkdir()

        with (
            patch("agentguard.cli.create_proxy_app") as mock_create,
            patch("uvicorn.run"),
        ):
            mock_create.return_value = "fake-app"
            exit_code = main(
                [
                    "proxy",
                    "https://api.anthropic.com",
                    "--host",
                    "0.0.0.0",
                    "--port",
                    "9090",
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
                    "60",
                ]
            )

        assert exit_code == 0
        config = mock_create.call_args[0][0]
        assert config.upstream_base_url == "https://api.anthropic.com"
        assert config.host == "0.0.0.0"
        assert config.port == 9090
        assert config.load_builtins is True
        assert config.auto_discover is True
        assert config.policy_dir == str(policy_dir)
        assert config.audit_dir == str(audit_dir)
        assert config.actor == "test-agent"
        assert config.scan_responses is True
        assert config.timeout == 60.0

    def test_proxy_unavailable_without_deps(self) -> None:
        """When proxy deps are missing, should show install instruction."""
        captured = io.StringIO()
        old_stderr = sys.stderr
        sys.stderr = captured
        with patch("agentguard.cli.create_proxy_app", None):
            try:
                exit_code = main(
                    [
                        "proxy",
                        "https://api.openai.com",
                    ]
                )
            finally:
                sys.stderr = old_stderr
        assert exit_code == 1
        assert "pip install agentguard[proxy]" in captured.getvalue()

    def test_proxy_auth_file_option(self, tmp_path: Path) -> None:
        """--auth-file option should be passed to ProxyConfig."""
        auth_file = tmp_path / "auth.json"
        auth_file.write_text('{"github-copilot": {"refresh": "gho_test"}}')

        with (
            patch("agentguard.cli.create_proxy_app") as mock_create,
            patch("uvicorn.run"),
        ):
            mock_create.return_value = "fake-app"
            exit_code = main(
                [
                    "proxy",
                    "https://api.githubcopilot.com",
                    "--auth-file",
                    str(auth_file),
                ]
            )

        assert exit_code == 0
        config = mock_create.call_args[0][0]
        assert config.auth_file == str(auth_file)

    def test_proxy_auth_provider_option(self, tmp_path: Path) -> None:
        """--auth-provider option should be passed to ProxyConfig."""
        auth_file = tmp_path / "auth.json"
        auth_file.write_text('{"anthropic": {"key": "sk-ant-test"}}')

        with (
            patch("agentguard.cli.create_proxy_app") as mock_create,
            patch("uvicorn.run"),
        ):
            mock_create.return_value = "fake-app"
            exit_code = main(
                [
                    "proxy",
                    "https://api.anthropic.com",
                    "--auth-file",
                    str(auth_file),
                    "--auth-provider",
                    "anthropic",
                ]
            )

        assert exit_code == 0
        config = mock_create.call_args[0][0]
        assert config.auth_file == str(auth_file)
        assert config.auth_provider == "anthropic"

    def test_proxy_auth_provider_default_github_copilot(self, tmp_path: Path) -> None:
        """--auth-provider should default to github-copilot."""
        auth_file = tmp_path / "auth.json"
        auth_file.write_text('{"github-copilot": {"refresh": "gho_test"}}')

        with (
            patch("agentguard.cli.create_proxy_app") as mock_create,
            patch("uvicorn.run"),
        ):
            mock_create.return_value = "fake-app"
            exit_code = main(
                [
                    "proxy",
                    "https://api.githubcopilot.com",
                    "--auth-file",
                    str(auth_file),
                ]
            )

        assert exit_code == 0
        config = mock_create.call_args[0][0]
        assert config.auth_provider == "github-copilot"
