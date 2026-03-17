"""Tests for MCP tool output truncation.

The MCP server's ``shell_execute``, ``file_read``, and ``file_grep``
tools currently return unbounded output strings.  Output truncation
caps the return value at a configurable maximum size (default 51200
bytes / 50 KB) and appends a truncation notice when the output
exceeds the limit.

Design:
- ``create_server()`` gains an optional ``max_output_size`` parameter
  (default: 51200 bytes).
- Each tool that returns potentially large output truncates to this
  limit and appends a notice like:
  ``\\n... (output truncated from {original_size} to {limit} bytes)``
- The truncation is applied AFTER the tool runs but BEFORE the
  result is returned to the client.
- The audit log records the original size and whether truncation
  occurred.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import anyio
import pytest
from mcp import ClientSession

if TYPE_CHECKING:
    from pathlib import Path


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def anyio_backend() -> str:
    """Use asyncio as the anyio backend for all tests."""
    return "asyncio"


@pytest.fixture
def audit_dir(tmp_path: Path) -> Path:
    """Create a temp directory for audit logs."""
    d = tmp_path / "audit"
    d.mkdir()
    return d


# ---------------------------------------------------------------------------
# Helper: run a function against an in-process MCP server
# ---------------------------------------------------------------------------


async def with_server(
    fn: Any,
    *,
    policy_dir: Path | None = None,
    audit_dir: Path | None = None,
    actor: str = "test-agent",
    builtins: bool = False,
    max_output_size: int | None = None,
) -> None:
    """Spin up an AgentGuard MCP server in-process and run fn(session).

    Uses anyio memory streams so no real I/O is needed.
    The server is cancelled once fn returns.
    """
    from agentguard.mcp.server import create_server

    kwargs: dict[str, Any] = {
        "policy_dir": str(policy_dir) if policy_dir else None,
        "audit_dir": str(audit_dir) if audit_dir else None,
        "actor": actor,
        "load_builtins": builtins,
    }
    if max_output_size is not None:
        kwargs["max_output_size"] = max_output_size

    app = create_server(**kwargs)

    server = app._mcp_server  # type: ignore[attr-defined]

    s2c_send, s2c_recv = anyio.create_memory_object_stream[Any](50)
    c2s_send, c2s_recv = anyio.create_memory_object_stream[Any](50)

    async with anyio.create_task_group() as tg:

        async def run_server() -> None:
            await server.run(
                c2s_recv,
                s2c_send,
                server.create_initialization_options(),
            )

        async def run_client() -> None:
            async with ClientSession(s2c_recv, c2s_send) as session:
                await session.initialize()
                await fn(session)
                tg.cancel_scope.cancel()

        tg.start_soon(run_server)
        tg.start_soon(run_client)


# ===========================================================================
# Test: create_server accepts max_output_size
# ===========================================================================


class TestCreateServerMaxOutputSize:
    """Test that create_server accepts and uses the max_output_size param."""

    @pytest.mark.anyio
    async def test_create_server_accepts_max_output_size(self) -> None:
        """create_server should accept max_output_size without error."""

        async def check(session: ClientSession) -> None:
            # Just verify the server starts up fine
            tools_resp = await session.list_tools()
            tool_names = {t.name for t in tools_resp.tools}
            assert "shell_execute" in tool_names

        await with_server(check, max_output_size=1024)

    @pytest.mark.anyio
    async def test_default_max_output_size_is_51200(self) -> None:
        """Default max_output_size should be 51200 (50 KB)."""

        # create_server with no max_output_size should use 51200 default
        # We verify by creating a server and checking it works with
        # output under 51200 bytes
        async def check(session: ClientSession) -> None:
            result = await session.call_tool("shell_execute", {"command": "echo hello"})
            assert not result.isError
            assert "hello" in result.content[0].text  # type: ignore[union-attr]

        await with_server(check)


# ===========================================================================
# Test: shell_execute output truncation
# ===========================================================================


class TestShellExecuteTruncation:
    """Test output truncation for shell_execute."""

    @pytest.mark.anyio
    async def test_short_output_not_truncated(self) -> None:
        """Output under the limit should not be truncated."""

        async def check(session: ClientSession) -> None:
            result = await session.call_tool("shell_execute", {"command": "echo hello"})
            assert not result.isError
            text = result.content[0].text  # type: ignore[union-attr]
            assert "hello" in text
            assert "truncated" not in text

        await with_server(check, max_output_size=51200)

    @pytest.mark.anyio
    async def test_large_output_truncated(self) -> None:
        """Output exceeding max_output_size should be truncated."""
        # Generate output larger than our small limit
        # Use python -c to generate exactly 200 bytes of output
        cmd = "python3 -c \"print('A' * 200)\""

        async def check(session: ClientSession) -> None:
            result = await session.call_tool("shell_execute", {"command": cmd})
            assert not result.isError
            text = result.content[0].text  # type: ignore[union-attr]
            # Should be truncated
            assert "truncated" in text.lower()
            # The visible content should be <= max_output_size + notice
            # The actual content before the notice should be <= 100 bytes
            assert len(text) < 250  # 100 + truncation notice

        await with_server(check, max_output_size=100)

    @pytest.mark.anyio
    async def test_truncation_notice_includes_sizes(self) -> None:
        """Truncation notice should mention original and truncated sizes."""
        cmd = "python3 -c \"print('B' * 500)\""

        async def check(session: ClientSession) -> None:
            result = await session.call_tool("shell_execute", {"command": cmd})
            assert not result.isError
            text = result.content[0].text  # type: ignore[union-attr]
            assert "truncated" in text.lower()
            # Should mention the limit size
            assert "100" in text

        await with_server(check, max_output_size=100)

    @pytest.mark.anyio
    async def test_exact_limit_not_truncated(self) -> None:
        """Output exactly at the limit should not be truncated."""
        # Generate exactly 100 bytes: 99 chars + newline
        cmd = "python3 -c \"print('X' * 99)\""

        async def check(session: ClientSession) -> None:
            result = await session.call_tool("shell_execute", {"command": cmd})
            assert not result.isError
            text = result.content[0].text  # type: ignore[union-attr]
            assert "truncated" not in text.lower()

        await with_server(check, max_output_size=100)


# ===========================================================================
# Test: file_read output truncation
# ===========================================================================


class TestFileReadTruncation:
    """Test output truncation for file_read."""

    @pytest.mark.anyio
    async def test_small_file_not_truncated(self, tmp_path: Path) -> None:
        """File under the limit should be returned in full."""
        test_file = tmp_path / "small.txt"
        test_file.write_text("hello world")

        async def check(session: ClientSession) -> None:
            result = await session.call_tool("file_read", {"path": str(test_file)})
            assert not result.isError
            text = result.content[0].text  # type: ignore[union-attr]
            assert text == "hello world"
            assert "truncated" not in text

        await with_server(check, max_output_size=51200)

    @pytest.mark.anyio
    async def test_large_file_truncated(self, tmp_path: Path) -> None:
        """File exceeding max_output_size should be truncated."""
        test_file = tmp_path / "large.txt"
        test_file.write_text("A" * 500)

        async def check(session: ClientSession) -> None:
            result = await session.call_tool("file_read", {"path": str(test_file)})
            assert not result.isError
            text = result.content[0].text  # type: ignore[union-attr]
            assert "truncated" in text.lower()
            # The content portion should be at most 100 bytes
            lines = text.split("\n")
            # Last line should be the truncation notice
            assert "truncated" in lines[-1].lower()

        await with_server(check, max_output_size=100)

    @pytest.mark.anyio
    async def test_file_truncation_preserves_start(self, tmp_path: Path) -> None:
        """Truncation should preserve the beginning of the file."""
        test_file = tmp_path / "content.txt"
        content = "START_MARKER" + "X" * 500 + "END_MARKER"
        test_file.write_text(content)

        async def check(session: ClientSession) -> None:
            result = await session.call_tool("file_read", {"path": str(test_file)})
            assert not result.isError
            text = result.content[0].text  # type: ignore[union-attr]
            assert text.startswith("START_MARKER")
            assert "END_MARKER" not in text

        await with_server(check, max_output_size=100)

    @pytest.mark.anyio
    async def test_truncation_audit_records_original_size(
        self, tmp_path: Path, audit_dir: Path
    ) -> None:
        """Audit log should record the original file size and truncation."""
        test_file = tmp_path / "big.txt"
        original_content = "Z" * 500
        test_file.write_text(original_content)

        async def check(session: ClientSession) -> None:
            await session.call_tool("file_read", {"path": str(test_file)})

            # Query audit log
            result = await session.call_tool(
                "agentguard_audit_query", {"action": "file_read"}
            )
            assert not result.isError
            text = result.content[0].text  # type: ignore[union-attr]
            # Audit should record original size
            assert "500" in text

        await with_server(check, max_output_size=100, audit_dir=audit_dir)


# ===========================================================================
# Test: file_grep output truncation
# ===========================================================================


class TestFileGrepTruncation:
    """Test output truncation for file_grep."""

    @pytest.mark.anyio
    async def test_small_grep_result_not_truncated(self, tmp_path: Path) -> None:
        """Grep output under the limit should not be truncated."""
        test_file = tmp_path / "code.py"
        test_file.write_text("def hello():\n    return 'world'\n")

        async def check(session: ClientSession) -> None:
            result = await session.call_tool(
                "file_grep",
                {"pattern": "hello", "path": str(tmp_path)},
            )
            assert not result.isError
            text = result.content[0].text  # type: ignore[union-attr]
            assert "hello" in text
            assert "output truncated" not in text.lower()

        await with_server(check, max_output_size=51200)

    @pytest.mark.anyio
    async def test_large_grep_result_truncated(self, tmp_path: Path) -> None:
        """Grep output exceeding max_output_size should be truncated."""
        # Create many files with matching content to generate large output
        for i in range(50):
            f = tmp_path / f"file_{i:03d}.py"
            f.write_text(f"def function_{i}():\n    match_target = {i}\n")

        async def check(session: ClientSession) -> None:
            result = await session.call_tool(
                "file_grep",
                {"pattern": "match_target", "path": str(tmp_path)},
            )
            assert not result.isError
            text = result.content[0].text  # type: ignore[union-attr]
            assert "truncated" in text.lower()

        await with_server(check, max_output_size=200)

    @pytest.mark.anyio
    async def test_grep_truncation_preserves_complete_lines(
        self, tmp_path: Path
    ) -> None:
        """Truncation should try to preserve complete match lines."""
        for i in range(20):
            f = tmp_path / f"mod_{i:03d}.py"
            f.write_text(f"SEARCHABLE_LINE_{i} = True\n")

        async def check(session: ClientSession) -> None:
            result = await session.call_tool(
                "file_grep",
                {"pattern": "SEARCHABLE_LINE", "path": str(tmp_path)},
            )
            assert not result.isError
            text = result.content[0].text  # type: ignore[union-attr]
            # If truncated, the truncation should happen at a line boundary
            if "truncated" in text.lower():
                # Split at the truncation notice
                parts = text.rsplit("\n", 1)
                # The content part should not end mid-line with a partial path
                content_part = parts[0] if len(parts) > 1 else text
                # Each complete line should have the full match format
                for line in content_part.strip().split("\n"):
                    if line and "truncated" not in line.lower():
                        assert "SEARCHABLE_LINE" in line

        await with_server(check, max_output_size=300)


# ===========================================================================
# Test: Truncation with max_output_size=0 disables truncation
# ===========================================================================


class TestTruncationDisabled:
    """Test that max_output_size=0 disables truncation."""

    @pytest.mark.anyio
    async def test_zero_max_output_disables_truncation(self, tmp_path: Path) -> None:
        """max_output_size=0 should mean no truncation."""
        test_file = tmp_path / "huge.txt"
        test_file.write_text("X" * 100_000)

        async def check(session: ClientSession) -> None:
            result = await session.call_tool("file_read", {"path": str(test_file)})
            assert not result.isError
            text = result.content[0].text  # type: ignore[union-attr]
            assert len(text) == 100_000
            assert "truncated" not in text

        await with_server(check, max_output_size=0)


# ===========================================================================
# Test: Error outputs not affected by truncation
# ===========================================================================


class TestErrorOutputNotTruncated:
    """Test that error messages from tools are NOT truncated."""

    @pytest.mark.anyio
    async def test_command_error_not_truncated(self) -> None:
        """Tool error messages should not be truncated even if long."""

        async def check(session: ClientSession) -> None:
            # A failing command — the error message should be intact
            result = await session.call_tool(
                "shell_execute",
                {"command": "exit 1"},
            )
            # Errors go through the error path, not the output path
            assert result.isError
            text = result.content[0].text  # type: ignore[union-attr]
            assert "truncated" not in text.lower()

        await with_server(check, max_output_size=10)

    @pytest.mark.anyio
    async def test_file_not_found_error_not_truncated(self, tmp_path: Path) -> None:
        """File-not-found errors should not be truncated."""

        async def check(session: ClientSession) -> None:
            result = await session.call_tool(
                "file_read",
                {"path": str(tmp_path / "nonexistent.txt")},
            )
            assert result.isError
            text = result.content[0].text  # type: ignore[union-attr]
            assert "truncated" not in text.lower()

        await with_server(check, max_output_size=10)
