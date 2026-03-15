"""SG-7: MCP Server Tool Integration.

Integration tests for MCP server tools with real Guard and
real AuditLog (no mocking of core components).

Tests invoke the MCP server's tools in-process via the FastMCP
Python API rather than over MCP transport.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agentguard.mcp.server import create_server

pytestmark = pytest.mark.integration


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _get_tool_fn(server, name: str):
    """Extract a registered tool function from FastMCP server.

    NOTE: This accesses the private ``server._tool_manager`` attribute,
    coupling these tests to FastMCP internals.  If the library changes
    the attribute name, these tests will need updating.
    """
    # FastMCP ToolManager exposes get_tool(name) method
    tool_manager = server._tool_manager
    tool = tool_manager.get_tool(name)
    if tool is None:
        msg = f"Tool '{name}' not found in server"
        raise KeyError(msg)
    return tool.fn


# ===========================================================================
# SG-7.1: shell_execute tool denied by Guard policy
# ===========================================================================


class TestShellExecuteDenied:
    """SG-7.1: shell_execute denied by no-force-push builtin."""

    def test_shell_execute_denied_by_builtin(self, tmp_path: Path) -> None:
        """shell_execute with 'git push --force' denied by Guard."""
        server = create_server(load_builtins=True)
        shell_execute = _get_tool_fn(server, "shell_execute")

        with pytest.raises(Exception, match="denied by policy"):
            shell_execute(command="git push --force origin main")

    def test_shell_execute_denial_recorded_in_audit(self, tmp_path: Path) -> None:
        """Denied shell_execute creates audit entry."""
        audit_dir = tmp_path / "audit"
        server = create_server(
            load_builtins=True,
            audit_dir=str(audit_dir),
        )
        shell_execute = _get_tool_fn(server, "shell_execute")

        with pytest.raises(Exception, match="denied by policy"):
            shell_execute(command="git push --force origin main")

        # Check audit files exist
        jsonl_files = list(audit_dir.glob("*.jsonl"))
        assert len(jsonl_files) == 1

        # Parse and verify
        entries = []
        for line in jsonl_files[0].read_text().strip().split("\n"):
            if line.strip():
                entries.append(json.loads(line))

        assert len(entries) == 1
        assert entries[0]["action"] == "shell_execute"
        assert entries[0]["result"] == "denied"


# ===========================================================================
# SG-7.2: file_write tool denied for secret content
# ===========================================================================


class TestFileWriteDenied:
    """SG-7.2: file_write denied for content containing secrets."""

    def test_file_write_denied_for_secret(self, tmp_path: Path) -> None:
        """file_write with API key content is denied."""
        server = create_server(load_builtins=True)
        file_write = _get_tool_fn(server, "file_write")

        target_file = str(tmp_path / "config.txt")

        with pytest.raises(Exception, match="denied by policy"):
            file_write(
                path=target_file,
                content="aws_secret_access_key=" + "AKIA" + "IOSFODNN7EXAMPLE",
            )

        # File was NOT written
        assert not Path(target_file).exists()


# ===========================================================================
# SG-7.3: agentguard_status returns correct state
# ===========================================================================


class TestAgentguardStatus:
    """SG-7.3: agentguard_status returns correct state."""

    def test_status_returns_correct_info(self, tmp_path: Path) -> None:
        """Status includes policy count, actor, session info."""
        server = create_server(
            load_builtins=True,
            actor="test-agent",
        )
        status_fn = _get_tool_fn(server, "agentguard_status")

        result = status_fn()
        data = json.loads(result)

        assert data["actor"] == "test-agent"
        assert data["policies_loaded"] > 0
        assert isinstance(data["policy_names"], list)
        assert len(data["policy_names"]) > 0
        assert data["session_id"].startswith("ag-")


# ===========================================================================
# SG-7.4: agentguard_audit_query filters correctly
# ===========================================================================


class TestAgentguardAuditQuery:
    """SG-7.4: agentguard_audit_query filters correctly."""

    def test_audit_query_filters_denied(self, tmp_path: Path) -> None:
        """Query with result=denied returns only denied entries."""
        server = create_server(load_builtins=True)

        shell_execute = _get_tool_fn(server, "shell_execute")
        file_write = _get_tool_fn(server, "file_write")
        file_read = _get_tool_fn(server, "file_read")
        audit_query = _get_tool_fn(server, "agentguard_audit_query")

        # Action 1: denied (force push)
        with pytest.raises((RuntimeError, Exception), match="denied by policy"):
            shell_execute(command="git push --force origin main")

        # Action 2: allowed (read a real file)
        test_file = tmp_path / "readable.txt"
        test_file.write_text("hello")
        file_read(path=str(test_file))

        # Action 3: denied (secret in file_write)
        with pytest.raises((RuntimeError, Exception), match="denied by policy"):
            file_write(
                path=str(tmp_path / "out.txt"),
                content="aws_secret_access_key=" + "AKIA" + "IOSFODNN7EXAMPLE",
            )

        # Query for denied entries only
        result = audit_query(result="denied")
        entries = json.loads(result)

        assert len(entries) == 2
        assert all(e["result"] == "denied" for e in entries)
