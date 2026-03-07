"""Tests for the ``python -m agentguard.mcp`` entry point."""

from __future__ import annotations

from unittest.mock import MagicMock, patch


class TestMCPMain:
    """Tests for agentguard.mcp.__main__ module."""

    def test_main_module_creates_and_runs_server(self) -> None:
        """Running ``python -m agentguard.mcp`` creates a server and runs it."""
        mock_app = MagicMock()
        mock_create = MagicMock(return_value=mock_app)

        with patch("agentguard.mcp.server.create_server", mock_create):
            import importlib

            import agentguard.mcp.__main__ as main_mod

            # Reset to count only the reload call
            mock_create.reset_mock()
            mock_app.reset_mock()
            importlib.reload(main_mod)

        mock_create.assert_called_once_with(
            load_builtins=True,
            auto_discover=True,
        )
        mock_app.run.assert_called_once()

    def test_main_module_is_importable(self) -> None:
        """The __main__ module should be importable without errors."""
        with patch("agentguard.mcp.server.create_server") as mock_create:
            mock_create.return_value = MagicMock()
            import importlib

            import agentguard.mcp.__main__ as main_mod

            importlib.reload(main_mod)
