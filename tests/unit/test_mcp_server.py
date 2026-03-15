"""Tests for AgentGuard MCP server.

Tests the transparent proxy MCP server that wraps shell execution,
file read, and file write tools with policy enforcement and audit
logging. Uses anyio memory streams for in-process client/server testing.
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
def policy_dir(tmp_path: Path) -> Path:
    """Create a temp directory with a test policy file."""
    d = tmp_path / "policies"
    d.mkdir()
    policy = d / "no-force-push.yaml"
    policy.write_text(
        "name: no-force-push\n"
        "description: Block destructive git operations\n"
        "rules:\n"
        "  - action: shell_execute\n"
        "    deny:\n"
        "      - pattern: 'git push.*--force'\n"
        "      - pattern: 'git push\\s+-f'\n"
        "      - pattern: 'git reset --hard'\n"
        "    severity: critical\n"
    )
    return d


@pytest.fixture
def secret_policy_dir(tmp_path: Path) -> Path:
    """Create a temp directory with a secret-exposure policy."""
    d = tmp_path / "policies"
    d.mkdir(exist_ok=True)
    policy = d / "no-secret-exposure.yaml"
    policy.write_text(
        "name: no-secret-exposure\n"
        "description: Block writing secrets\n"
        "rules:\n"
        "  - action: file_write\n"
        "    deny:\n"
        "      - pattern: '\\.env$'\n"
        "      - pattern: 'credentials'\n"
        "    severity: critical\n"
    )
    return d


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
    trust_registry: str | None = None,
) -> None:
    """Spin up an AgentGuard MCP server in-process and run fn(session).

    Uses anyio memory streams so no real I/O is needed.
    The server is cancelled once fn returns.
    """
    from agentguard.mcp.server import create_server

    app = create_server(
        policy_dir=str(policy_dir) if policy_dir else None,
        audit_dir=str(audit_dir) if audit_dir else None,
        actor=actor,
        load_builtins=builtins,
        trust_registry=trust_registry,
    )

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
# Test: Tool parameter definitions for new tools
# ===========================================================================


class TestNewToolDefinitions:
    """Test that new MCP tools have the expected parameter schemas."""

    @pytest.mark.anyio
    async def test_file_edit_tool_has_expected_params(self) -> None:
        """file_edit should accept path, old_string, new_string, replace_all."""

        async def check(session: ClientSession) -> None:
            tools_resp = await session.list_tools()
            edit = next(t for t in tools_resp.tools if t.name == "file_edit")
            props = edit.inputSchema.get("properties", {})
            assert "path" in props
            assert "old_string" in props
            assert "new_string" in props
            assert "replace_all" in props

        await with_server(check)

    @pytest.mark.anyio
    async def test_file_glob_tool_has_expected_params(self) -> None:
        """file_glob should accept pattern and optional path."""

        async def check(session: ClientSession) -> None:
            tools_resp = await session.list_tools()
            glob_tool = next(t for t in tools_resp.tools if t.name == "file_glob")
            props = glob_tool.inputSchema.get("properties", {})
            assert "pattern" in props
            assert "path" in props

        await with_server(check)

    @pytest.mark.anyio
    async def test_file_grep_tool_has_expected_params(self) -> None:
        """file_grep should accept pattern, optional path, optional include."""

        async def check(session: ClientSession) -> None:
            tools_resp = await session.list_tools()
            grep_tool = next(t for t in tools_resp.tools if t.name == "file_grep")
            props = grep_tool.inputSchema.get("properties", {})
            assert "pattern" in props
            assert "path" in props
            assert "include" in props

        await with_server(check)

    @pytest.mark.anyio
    async def test_file_list_tool_has_expected_params(self) -> None:
        """file_list should accept optional path."""

        async def check(session: ClientSession) -> None:
            tools_resp = await session.list_tools()
            list_tool = next(t for t in tools_resp.tools if t.name == "file_list")
            props = list_tool.inputSchema.get("properties", {})
            assert "path" in props

        await with_server(check)


# ===========================================================================
# Test: File edit
# ===========================================================================


class TestFileEdit:
    """Test the file_edit tool."""

    @pytest.mark.anyio
    async def test_edit_replaces_string(self, tmp_path: Path) -> None:
        """Should replace old_string with new_string in a file."""
        target = tmp_path / "edit_test.txt"
        target.write_text("hello world")

        async def check(session: ClientSession) -> None:
            result = await session.call_tool(
                "file_edit",
                {
                    "path": str(target),
                    "old_string": "hello",
                    "new_string": "goodbye",
                },
            )
            assert not result.isError
            assert target.read_text() == "goodbye world"

        await with_server(check)

    @pytest.mark.anyio
    async def test_edit_nonexistent_file_errors(self, tmp_path: Path) -> None:
        """Should error when file does not exist."""

        async def check(session: ClientSession) -> None:
            result = await session.call_tool(
                "file_edit",
                {
                    "path": str(tmp_path / "missing.txt"),
                    "old_string": "a",
                    "new_string": "b",
                },
            )
            assert result.isError

        await with_server(check)

    @pytest.mark.anyio
    async def test_edit_string_not_found_errors(self, tmp_path: Path) -> None:
        """Should error when old_string is not found in the file."""
        target = tmp_path / "no_match.txt"
        target.write_text("foo bar")

        async def check(session: ClientSession) -> None:
            result = await session.call_tool(
                "file_edit",
                {
                    "path": str(target),
                    "old_string": "xyz",
                    "new_string": "abc",
                },
            )
            assert result.isError

        await with_server(check)

    @pytest.mark.anyio
    async def test_edit_identical_strings_errors(self, tmp_path: Path) -> None:
        """Should error when old_string equals new_string."""
        target = tmp_path / "identical.txt"
        target.write_text("hello")

        async def check(session: ClientSession) -> None:
            result = await session.call_tool(
                "file_edit",
                {
                    "path": str(target),
                    "old_string": "hello",
                    "new_string": "hello",
                },
            )
            assert result.isError

        await with_server(check)

    @pytest.mark.anyio
    async def test_edit_multiple_matches_errors_without_replace_all(
        self, tmp_path: Path
    ) -> None:
        """Should error when multiple matches found and replace_all is False."""
        target = tmp_path / "multi.txt"
        target.write_text("abc abc abc")

        async def check(session: ClientSession) -> None:
            result = await session.call_tool(
                "file_edit",
                {
                    "path": str(target),
                    "old_string": "abc",
                    "new_string": "xyz",
                },
            )
            assert result.isError
            # File should be unchanged
            assert target.read_text() == "abc abc abc"

        await with_server(check)

    @pytest.mark.anyio
    async def test_edit_replace_all_replaces_all_occurrences(
        self, tmp_path: Path
    ) -> None:
        """Should replace all occurrences when replace_all is True."""
        target = tmp_path / "replace_all.txt"
        target.write_text("abc abc abc")

        async def check(session: ClientSession) -> None:
            result = await session.call_tool(
                "file_edit",
                {
                    "path": str(target),
                    "old_string": "abc",
                    "new_string": "xyz",
                    "replace_all": True,
                },
            )
            assert not result.isError
            assert target.read_text() == "xyz xyz xyz"

        await with_server(check)

    @pytest.mark.anyio
    async def test_edit_preserves_rest_of_file(self, tmp_path: Path) -> None:
        """Edit should only change the matched portion, leaving rest intact."""
        target = tmp_path / "partial.txt"
        target.write_text("line1\nline2\nline3\n")

        async def check(session: ClientSession) -> None:
            result = await session.call_tool(
                "file_edit",
                {
                    "path": str(target),
                    "old_string": "line2",
                    "new_string": "REPLACED",
                },
            )
            assert not result.isError
            assert target.read_text() == "line1\nREPLACED\nline3\n"

        await with_server(check)

    @pytest.mark.anyio
    async def test_edit_is_audited(self, tmp_path: Path, audit_dir: Path) -> None:
        """Edit actions should appear in the audit log."""
        target = tmp_path / "audited.txt"
        target.write_text("before")

        async def check(session: ClientSession) -> None:
            await session.call_tool(
                "file_edit",
                {
                    "path": str(target),
                    "old_string": "before",
                    "new_string": "after",
                },
            )
            result = await session.call_tool(
                "agentguard_audit_query", {"action": "file_edit"}
            )
            assert not result.isError
            text = result.content[0].text  # type: ignore[union-attr]
            assert "file_edit" in text
            assert "allowed" in text

        await with_server(check, audit_dir=audit_dir)

    @pytest.mark.anyio
    async def test_edit_denied_by_policy(self, tmp_path: Path) -> None:
        """Edit should be blocked by a matching deny policy."""
        policy_d = tmp_path / "policies"
        policy_d.mkdir()
        (policy_d / "block-edit.yaml").write_text(
            "name: block-edit\n"
            "description: Block editing sensitive files\n"
            "rules:\n"
            "  - action: file_edit\n"
            "    deny:\n"
            "      - pattern: 'secret'\n"
            "    severity: critical\n"
        )
        target = tmp_path / "secret_config.txt"
        target.write_text("password=old")

        async def check(session: ClientSession) -> None:
            result = await session.call_tool(
                "file_edit",
                {
                    "path": str(target),
                    "old_string": "password=old",
                    "new_string": "password=new",
                },
            )
            assert result.isError
            # File should be unchanged
            assert target.read_text() == "password=old"

        await with_server(check, policy_dir=policy_d)


# ===========================================================================
# Test: File glob
# ===========================================================================


class TestFileGlob:
    """Test the file_glob tool."""

    @pytest.mark.anyio
    async def test_glob_finds_matching_files(self, tmp_path: Path) -> None:
        """Should find files matching a glob pattern."""
        (tmp_path / "file1.py").write_text("# python")
        (tmp_path / "file2.py").write_text("# python")
        (tmp_path / "file3.txt").write_text("text")

        async def check(session: ClientSession) -> None:
            result = await session.call_tool(
                "file_glob",
                {"pattern": "**/*.py", "path": str(tmp_path)},
            )
            assert not result.isError
            text = result.content[0].text  # type: ignore[union-attr]
            assert "file1.py" in text
            assert "file2.py" in text
            assert "file3.txt" not in text

        await with_server(check)

    @pytest.mark.anyio
    async def test_glob_no_matches_returns_empty(self, tmp_path: Path) -> None:
        """Should return empty/no-matches message when no files match."""
        (tmp_path / "file.txt").write_text("text")

        async def check(session: ClientSession) -> None:
            result = await session.call_tool(
                "file_glob",
                {"pattern": "**/*.rs", "path": str(tmp_path)},
            )
            assert not result.isError
            text = result.content[0].text  # type: ignore[union-attr]
            assert "no" in text.lower() or text.strip() == "" or "0" in text

        await with_server(check)

    @pytest.mark.anyio
    async def test_glob_nested_directories(self, tmp_path: Path) -> None:
        """Should find files in nested subdirectories."""
        sub = tmp_path / "sub" / "deep"
        sub.mkdir(parents=True)
        (sub / "found.py").write_text("# found")

        async def check(session: ClientSession) -> None:
            result = await session.call_tool(
                "file_glob",
                {"pattern": "**/*.py", "path": str(tmp_path)},
            )
            assert not result.isError
            assert "found.py" in result.content[0].text  # type: ignore[union-attr]

        await with_server(check)

    @pytest.mark.anyio
    async def test_glob_caps_results_at_100(self, tmp_path: Path) -> None:
        """Should cap results at 100 files."""
        for i in range(120):
            (tmp_path / f"file_{i:03d}.txt").write_text(f"content {i}")

        async def check(session: ClientSession) -> None:
            result = await session.call_tool(
                "file_glob",
                {"pattern": "**/*.txt", "path": str(tmp_path)},
            )
            assert not result.isError
            text = result.content[0].text  # type: ignore[union-attr]
            # Should have at most 100 file entries
            lines = [ln for ln in text.strip().split("\n") if ln.strip()]
            assert len(lines) <= 101  # 100 files + possible truncation msg

        await with_server(check)

    @pytest.mark.anyio
    async def test_glob_is_audited(self, tmp_path: Path, audit_dir: Path) -> None:
        """Glob actions should appear in the audit log."""
        (tmp_path / "test.py").write_text("# test")

        async def check(session: ClientSession) -> None:
            await session.call_tool(
                "file_glob",
                {"pattern": "**/*.py", "path": str(tmp_path)},
            )
            result = await session.call_tool(
                "agentguard_audit_query", {"action": "file_glob"}
            )
            assert not result.isError
            text = result.content[0].text  # type: ignore[union-attr]
            assert "file_glob" in text

        await with_server(check, audit_dir=audit_dir)

    @pytest.mark.anyio
    async def test_glob_denied_by_policy(self, tmp_path: Path) -> None:
        """Glob should be blocked by a matching deny policy."""
        policy_d = tmp_path / "policies"
        policy_d.mkdir()
        (policy_d / "block-glob.yaml").write_text(
            "name: block-glob\n"
            "description: Block glob on private dirs\n"
            "rules:\n"
            "  - action: file_glob\n"
            "    deny:\n"
            "      - pattern: 'private'\n"
            "    severity: high\n"
        )

        async def check(session: ClientSession) -> None:
            result = await session.call_tool(
                "file_glob",
                {"pattern": "**/*", "path": str(tmp_path / "private")},
            )
            assert result.isError

        await with_server(check, policy_dir=policy_d)


# ===========================================================================
# Test: File grep
# ===========================================================================


class TestFileGrep:
    """Test the file_grep tool."""

    @pytest.mark.anyio
    async def test_grep_finds_matching_content(self, tmp_path: Path) -> None:
        """Should find files containing the search pattern."""
        (tmp_path / "match.py").write_text("def hello():\n    return 'hi'\n")
        (tmp_path / "no_match.py").write_text("def goodbye():\n    return 'bye'\n")

        async def check(session: ClientSession) -> None:
            result = await session.call_tool(
                "file_grep",
                {"pattern": "hello", "path": str(tmp_path)},
            )
            assert not result.isError
            text = result.content[0].text  # type: ignore[union-attr]
            assert "match.py" in text
            assert "hello" in text

        await with_server(check)

    @pytest.mark.anyio
    async def test_grep_no_matches(self, tmp_path: Path) -> None:
        """Should indicate no matches when pattern not found."""
        (tmp_path / "file.py").write_text("nothing here")

        async def check(session: ClientSession) -> None:
            result = await session.call_tool(
                "file_grep",
                {"pattern": "nonexistent_pattern_xyz", "path": str(tmp_path)},
            )
            assert not result.isError
            text = result.content[0].text  # type: ignore[union-attr]
            assert "no" in text.lower() or text.strip() == "" or "0" in text

        await with_server(check)

    @pytest.mark.anyio
    async def test_grep_with_include_filter(self, tmp_path: Path) -> None:
        """Should only search files matching the include pattern."""
        (tmp_path / "match.py").write_text("target_string")
        (tmp_path / "match.txt").write_text("target_string")

        async def check(session: ClientSession) -> None:
            result = await session.call_tool(
                "file_grep",
                {
                    "pattern": "target_string",
                    "path": str(tmp_path),
                    "include": "*.py",
                },
            )
            assert not result.isError
            text = result.content[0].text  # type: ignore[union-attr]
            assert "match.py" in text
            assert "match.txt" not in text

        await with_server(check)

    @pytest.mark.anyio
    async def test_grep_returns_line_numbers(self, tmp_path: Path) -> None:
        """Should include line numbers in the results."""
        (tmp_path / "lined.py").write_text("line1\nline2\ntarget\nline4\n")

        async def check(session: ClientSession) -> None:
            result = await session.call_tool(
                "file_grep",
                {"pattern": "target", "path": str(tmp_path)},
            )
            assert not result.isError
            text = result.content[0].text  # type: ignore[union-attr]
            # Should contain line number 3
            assert "3" in text

        await with_server(check)

    @pytest.mark.anyio
    async def test_grep_regex_patterns(self, tmp_path: Path) -> None:
        """Should support regex patterns."""
        (tmp_path / "regex_test.py").write_text(
            "def func_one():\n    pass\ndef func_two():\n    pass\n"
        )

        async def check(session: ClientSession) -> None:
            result = await session.call_tool(
                "file_grep",
                {"pattern": "def func_\\w+", "path": str(tmp_path)},
            )
            assert not result.isError
            text = result.content[0].text  # type: ignore[union-attr]
            assert "func_one" in text or "func_two" in text

        await with_server(check)

    @pytest.mark.anyio
    async def test_grep_nested_directories(self, tmp_path: Path) -> None:
        """Should search files in nested subdirectories."""
        sub = tmp_path / "sub" / "deep"
        sub.mkdir(parents=True)
        (sub / "nested.py").write_text("nested_target_value")

        async def check(session: ClientSession) -> None:
            result = await session.call_tool(
                "file_grep",
                {"pattern": "nested_target_value", "path": str(tmp_path)},
            )
            assert not result.isError
            assert "nested.py" in result.content[0].text  # type: ignore[union-attr]

        await with_server(check)

    @pytest.mark.anyio
    async def test_grep_is_audited(self, tmp_path: Path, audit_dir: Path) -> None:
        """Grep actions should appear in the audit log."""
        (tmp_path / "test.py").write_text("searchable content")

        async def check(session: ClientSession) -> None:
            await session.call_tool(
                "file_grep",
                {"pattern": "searchable", "path": str(tmp_path)},
            )
            result = await session.call_tool(
                "agentguard_audit_query", {"action": "file_grep"}
            )
            assert not result.isError
            text = result.content[0].text  # type: ignore[union-attr]
            assert "file_grep" in text

        await with_server(check, audit_dir=audit_dir)

    @pytest.mark.anyio
    async def test_grep_denied_by_policy(self, tmp_path: Path) -> None:
        """Grep should be blocked by a matching deny policy."""
        policy_d = tmp_path / "policies"
        policy_d.mkdir()
        (policy_d / "block-grep.yaml").write_text(
            "name: block-grep\n"
            "description: Block grep for secrets\n"
            "rules:\n"
            "  - action: file_grep\n"
            "    deny:\n"
            "      - pattern: 'password'\n"
            "    severity: critical\n"
        )

        async def check(session: ClientSession) -> None:
            result = await session.call_tool(
                "file_grep",
                {"pattern": "password", "path": str(tmp_path)},
            )
            assert result.isError

        await with_server(check, policy_dir=policy_d)

    @pytest.mark.anyio
    async def test_grep_caps_results_at_100(self, tmp_path: Path) -> None:
        """Should cap results at 100 matches."""
        for i in range(120):
            (tmp_path / f"file_{i:03d}.txt").write_text(f"findme content {i}")

        async def check(session: ClientSession) -> None:
            result = await session.call_tool(
                "file_grep",
                {"pattern": "findme", "path": str(tmp_path)},
            )
            assert not result.isError
            text = result.content[0].text  # type: ignore[union-attr]
            # Output should be capped
            lines = [ln for ln in text.strip().split("\n") if ln.strip()]
            assert len(lines) <= 110  # some overhead for headers

        await with_server(check)


# ===========================================================================
# Test: File list
# ===========================================================================


class TestFileList:
    """Test the file_list tool."""

    @pytest.mark.anyio
    async def test_list_directory_contents(self, tmp_path: Path) -> None:
        """Should list files and directories in the given path."""
        (tmp_path / "file1.py").write_text("# python")
        (tmp_path / "file2.txt").write_text("text")
        (tmp_path / "subdir").mkdir()

        async def check(session: ClientSession) -> None:
            result = await session.call_tool(
                "file_list",
                {"path": str(tmp_path)},
            )
            assert not result.isError
            text = result.content[0].text  # type: ignore[union-attr]
            assert "file1.py" in text
            assert "file2.txt" in text
            assert "subdir" in text

        await with_server(check)

    @pytest.mark.anyio
    async def test_list_marks_directories(self, tmp_path: Path) -> None:
        """Should mark directories with trailing /."""
        (tmp_path / "mydir").mkdir()
        (tmp_path / "myfile.txt").write_text("text")

        async def check(session: ClientSession) -> None:
            result = await session.call_tool(
                "file_list",
                {"path": str(tmp_path)},
            )
            assert not result.isError
            text = result.content[0].text  # type: ignore[union-attr]
            assert "mydir/" in text
            # File should NOT have trailing /
            lines = text.strip().split("\n")
            file_lines = [ln for ln in lines if "myfile.txt" in ln]
            for fl in file_lines:
                assert not fl.strip().endswith("/") or "myfile.txt/" not in fl

        await with_server(check)

    @pytest.mark.anyio
    async def test_list_empty_directory(self, tmp_path: Path) -> None:
        """Should handle empty directories gracefully."""
        empty = tmp_path / "empty"
        empty.mkdir()

        async def check(session: ClientSession) -> None:
            result = await session.call_tool(
                "file_list",
                {"path": str(empty)},
            )
            assert not result.isError

        await with_server(check)

    @pytest.mark.anyio
    async def test_list_nonexistent_path_errors(self, tmp_path: Path) -> None:
        """Should error for a nonexistent directory."""

        async def check(session: ClientSession) -> None:
            result = await session.call_tool(
                "file_list",
                {"path": str(tmp_path / "does_not_exist")},
            )
            assert result.isError

        await with_server(check)

    @pytest.mark.anyio
    async def test_list_caps_at_100_entries(self, tmp_path: Path) -> None:
        """Should cap at 100 entries."""
        for i in range(120):
            (tmp_path / f"file_{i:03d}.txt").write_text(f"content {i}")

        async def check(session: ClientSession) -> None:
            result = await session.call_tool(
                "file_list",
                {"path": str(tmp_path)},
            )
            assert not result.isError
            text = result.content[0].text  # type: ignore[union-attr]
            lines = [ln for ln in text.strip().split("\n") if ln.strip()]
            assert len(lines) <= 101  # 100 entries + possible truncation msg

        await with_server(check)

    @pytest.mark.anyio
    async def test_list_is_audited(self, tmp_path: Path, audit_dir: Path) -> None:
        """List actions should appear in the audit log."""
        (tmp_path / "test.py").write_text("# test")

        async def check(session: ClientSession) -> None:
            await session.call_tool(
                "file_list",
                {"path": str(tmp_path)},
            )
            result = await session.call_tool(
                "agentguard_audit_query", {"action": "file_list"}
            )
            assert not result.isError
            text = result.content[0].text  # type: ignore[union-attr]
            assert "file_list" in text

        await with_server(check, audit_dir=audit_dir)

    @pytest.mark.anyio
    async def test_list_denied_by_policy(self, tmp_path: Path) -> None:
        """List should be blocked by a matching deny policy."""
        policy_d = tmp_path / "policies"
        policy_d.mkdir()
        (policy_d / "block-list.yaml").write_text(
            "name: block-list\n"
            "description: Block listing private dirs\n"
            "rules:\n"
            "  - action: file_list\n"
            "    deny:\n"
            "      - pattern: 'private'\n"
            "    severity: high\n"
        )

        async def check(session: ClientSession) -> None:
            result = await session.call_tool(
                "file_list",
                {"path": str(tmp_path / "private")},
            )
            assert result.isError

        await with_server(check, policy_dir=policy_d)


# ===========================================================================
# Test: Server creation and tool listing
# ===========================================================================


class TestServerToolDefinitions:
    """Test that the MCP server exposes the expected tools."""

    @pytest.mark.anyio
    async def test_server_lists_tools(self) -> None:
        """Server should expose all 9 tools: shell_execute, file_read,
        file_write, file_edit, file_glob, file_grep, file_list,
        agentguard_status, agentguard_audit_query,
        agentguard_trust_query, and agentguard_scan_package."""

        async def check(session: ClientSession) -> None:
            tools_resp = await session.list_tools()
            tool_names = {t.name for t in tools_resp.tools}
            assert "shell_execute" in tool_names
            assert "file_read" in tool_names
            assert "file_write" in tool_names
            assert "file_edit" in tool_names
            assert "file_glob" in tool_names
            assert "file_grep" in tool_names
            assert "file_list" in tool_names
            assert "agentguard_status" in tool_names
            assert "agentguard_audit_query" in tool_names
            assert "agentguard_trust_query" in tool_names
            assert "agentguard_scan_package" in tool_names

        await with_server(check)

    @pytest.mark.anyio
    async def test_shell_execute_tool_has_command_param(self) -> None:
        """shell_execute should accept a 'command' parameter."""

        async def check(session: ClientSession) -> None:
            tools_resp = await session.list_tools()
            shell = next(t for t in tools_resp.tools if t.name == "shell_execute")
            assert "command" in shell.inputSchema.get("properties", {})

        await with_server(check)

    @pytest.mark.anyio
    async def test_file_read_tool_has_path_param(self) -> None:
        """file_read should accept a 'path' parameter."""

        async def check(session: ClientSession) -> None:
            tools_resp = await session.list_tools()
            read = next(t for t in tools_resp.tools if t.name == "file_read")
            assert "path" in read.inputSchema.get("properties", {})

        await with_server(check)

    @pytest.mark.anyio
    async def test_file_write_tool_has_path_and_content_params(self) -> None:
        """file_write should accept 'path' and 'content' parameters."""

        async def check(session: ClientSession) -> None:
            tools_resp = await session.list_tools()
            write = next(t for t in tools_resp.tools if t.name == "file_write")
            props = write.inputSchema.get("properties", {})
            assert "path" in props
            assert "content" in props

        await with_server(check)


# ===========================================================================
# Test: Shell execution
# ===========================================================================


class TestShellExecute:
    """Test the shell_execute tool."""

    @pytest.mark.anyio
    async def test_execute_simple_command(self) -> None:
        """Should execute a simple shell command and return output."""

        async def check(session: ClientSession) -> None:
            result = await session.call_tool("shell_execute", {"command": "echo hello"})
            assert not result.isError
            assert "hello" in result.content[0].text  # type: ignore[union-attr]

        await with_server(check)

    @pytest.mark.anyio
    async def test_execute_uses_bash_when_available(self) -> None:
        """shell_execute should prefer bash over the default shell."""
        import shutil
        from unittest.mock import patch

        bash_path = shutil.which("bash")
        if bash_path is None:
            pytest.skip("bash not available on this system")

        with patch("agentguard.mcp.server.subprocess.run") as mock_run:
            mock_run.return_value = type(
                "CompletedProcess",
                (),
                {"returncode": 0, "stdout": "mocked\n", "stderr": ""},
            )()

            async def check(session: ClientSession) -> None:
                await session.call_tool("shell_execute", {"command": "echo mocked"})
                mock_run.assert_called_once()
                call_kwargs = mock_run.call_args
                assert call_kwargs.kwargs.get("executable") == bash_path

            await with_server(check)

    @pytest.mark.anyio
    async def test_execute_failing_command(self) -> None:
        """Should report error for non-zero exit code."""

        async def check(session: ClientSession) -> None:
            result = await session.call_tool("shell_execute", {"command": "exit 1"})
            text = result.content[0].text  # type: ignore[union-attr]
            # Either isError or the output mentions the exit code
            assert result.isError or "1" in text

        await with_server(check)

    @pytest.mark.anyio
    async def test_execute_multiline_output(self) -> None:
        """Should capture multi-line command output."""

        async def check(session: ClientSession) -> None:
            result = await session.call_tool(
                "shell_execute",
                {"command": "echo line1 && echo line2"},
            )
            assert not result.isError
            text = result.content[0].text  # type: ignore[union-attr]
            assert "line1" in text
            assert "line2" in text

        await with_server(check)


# ===========================================================================
# Test: File read
# ===========================================================================


class TestFileRead:
    """Test the file_read tool."""

    @pytest.mark.anyio
    async def test_read_existing_file(self, tmp_path: Path) -> None:
        """Should read the contents of an existing file."""
        test_file = tmp_path / "test.txt"
        test_file.write_text("hello world")

        async def check(session: ClientSession) -> None:
            result = await session.call_tool("file_read", {"path": str(test_file)})
            assert not result.isError
            assert "hello world" in result.content[0].text  # type: ignore[union-attr]

        await with_server(check)

    @pytest.mark.anyio
    async def test_read_nonexistent_file(self, tmp_path: Path) -> None:
        """Should return error for non-existent file."""

        async def check(session: ClientSession) -> None:
            result = await session.call_tool(
                "file_read", {"path": str(tmp_path / "nonexistent.txt")}
            )
            assert result.isError

        await with_server(check)

    @pytest.mark.anyio
    async def test_read_binary_file_rejected(self, tmp_path: Path) -> None:
        """Should reject binary files."""
        bin_file = tmp_path / "data.bin"
        bin_file.write_bytes(b"\x00\x01\x02\xff\xfe")

        async def check(session: ClientSession) -> None:
            result = await session.call_tool("file_read", {"path": str(bin_file)})
            assert result.isError

        await with_server(check)


# ===========================================================================
# Test: File write
# ===========================================================================


class TestFileWrite:
    """Test the file_write tool."""

    @pytest.mark.anyio
    async def test_write_new_file(self, tmp_path: Path) -> None:
        """Should create a new file with given content."""
        target = tmp_path / "output.txt"

        async def check(session: ClientSession) -> None:
            result = await session.call_tool(
                "file_write",
                {"path": str(target), "content": "hello from agentguard"},
            )
            assert not result.isError
            assert target.read_text() == "hello from agentguard"

        await with_server(check)

    @pytest.mark.anyio
    async def test_write_overwrites_existing(self, tmp_path: Path) -> None:
        """Should overwrite existing file content."""
        target = tmp_path / "existing.txt"
        target.write_text("old content")

        async def check(session: ClientSession) -> None:
            result = await session.call_tool(
                "file_write",
                {"path": str(target), "content": "new content"},
            )
            assert not result.isError
            assert target.read_text() == "new content"

        await with_server(check)

    @pytest.mark.anyio
    async def test_write_creates_parent_dirs(self, tmp_path: Path) -> None:
        """Should create parent directories if they don't exist."""
        target = tmp_path / "sub" / "deep" / "file.txt"

        async def check(session: ClientSession) -> None:
            result = await session.call_tool(
                "file_write",
                {"path": str(target), "content": "nested"},
            )
            assert not result.isError
            assert target.read_text() == "nested"

        await with_server(check)


# ===========================================================================
# Test: Policy enforcement
# ===========================================================================


class TestPolicyEnforcement:
    """Test that the policy engine blocks denied actions."""

    @pytest.mark.anyio
    async def test_denied_shell_command_is_blocked(self, policy_dir: Path) -> None:
        """A shell command matching a deny policy should be blocked."""

        async def check(session: ClientSession) -> None:
            result = await session.call_tool(
                "shell_execute",
                {"command": "git push --force origin main"},
            )
            assert result.isError
            text = result.content[0].text  # type: ignore[union-attr]
            assert "denied" in text.lower() or "blocked" in text.lower()

        await with_server(check, policy_dir=policy_dir)

    @pytest.mark.anyio
    async def test_allowed_shell_command_executes(self, policy_dir: Path) -> None:
        """A command NOT matching any deny policy should execute."""

        async def check(session: ClientSession) -> None:
            result = await session.call_tool(
                "shell_execute", {"command": "echo allowed"}
            )
            assert not result.isError
            assert "allowed" in result.content[0].text  # type: ignore[union-attr]

        await with_server(check, policy_dir=policy_dir)

    @pytest.mark.anyio
    async def test_denied_file_write_is_blocked(
        self, secret_policy_dir: Path, tmp_path: Path
    ) -> None:
        """Writing to a path matching deny policy should be blocked."""
        target = tmp_path / ".env"

        async def check(session: ClientSession) -> None:
            result = await session.call_tool(
                "file_write",
                {"path": str(target), "content": "SECRET=abc123"},
            )
            assert result.isError
            assert not target.exists()

        await with_server(check, policy_dir=secret_policy_dir)

    @pytest.mark.anyio
    async def test_denied_action_includes_policy_name(self, policy_dir: Path) -> None:
        """Denial message should include the policy name."""

        async def check(session: ClientSession) -> None:
            result = await session.call_tool(
                "shell_execute",
                {"command": "git push --force origin main"},
            )
            assert result.isError
            assert "no-force-push" in result.content[0].text  # type: ignore[union-attr]

        await with_server(check, policy_dir=policy_dir)

    @pytest.mark.anyio
    async def test_load_builtin_policies(self) -> None:
        """Server with load_builtins=True should block built-in violations."""

        async def check(session: ClientSession) -> None:
            result = await session.call_tool(
                "shell_execute",
                {"command": "git push --force origin main"},
            )
            assert result.isError

        await with_server(check, builtins=True)

    @pytest.mark.anyio
    async def test_no_policies_allows_all(self) -> None:
        """Server with no policies should allow all actions."""

        async def check(session: ClientSession) -> None:
            result = await session.call_tool("shell_execute", {"command": "echo free"})
            assert not result.isError

        await with_server(check)


# ===========================================================================
# Test: Audit logging
# ===========================================================================


class TestAuditLogging:
    """Test that all tool calls are audit-logged."""

    @pytest.mark.anyio
    async def test_allowed_action_is_logged(self, audit_dir: Path) -> None:
        """An allowed action should appear in the audit log."""

        async def check(session: ClientSession) -> None:
            await session.call_tool("shell_execute", {"command": "echo logged"})
            result = await session.call_tool(
                "agentguard_audit_query", {"action": "shell_execute"}
            )
            assert not result.isError
            text = result.content[0].text  # type: ignore[union-attr]
            assert "shell_execute" in text
            assert "allowed" in text

        await with_server(check, audit_dir=audit_dir)

    @pytest.mark.anyio
    async def test_denied_action_is_logged(
        self, policy_dir: Path, audit_dir: Path
    ) -> None:
        """A denied action should still appear in the audit log."""

        async def check(session: ClientSession) -> None:
            await session.call_tool(
                "shell_execute",
                {"command": "git push --force origin main"},
            )
            result = await session.call_tool(
                "agentguard_audit_query", {"result": "denied"}
            )
            assert not result.isError
            assert "denied" in result.content[0].text  # type: ignore[union-attr]

        await with_server(check, policy_dir=policy_dir, audit_dir=audit_dir)

    @pytest.mark.anyio
    async def test_audit_log_records_actor(self, audit_dir: Path) -> None:
        """Audit entries should include the configured actor name."""

        async def check(session: ClientSession) -> None:
            await session.call_tool("shell_execute", {"command": "echo test"})
            result = await session.call_tool("agentguard_audit_query", {})
            assert "my-custom-agent" in result.content[0].text  # type: ignore[union-attr]

        await with_server(check, audit_dir=audit_dir, actor="my-custom-agent")

    @pytest.mark.anyio
    async def test_audit_log_saves_to_disk(self, audit_dir: Path) -> None:
        """When audit_dir is configured, JSONL files should be written."""
        from agentguard.mcp.server import create_server

        app = create_server(audit_dir=str(audit_dir))
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
                    await session.call_tool(
                        "shell_execute", {"command": "echo persist"}
                    )
                    tg.cancel_scope.cancel()

            tg.start_soon(run_server)
            tg.start_soon(run_client)

        # After session ends, audit should be saved
        jsonl_files = list(audit_dir.glob("*.jsonl"))
        assert len(jsonl_files) >= 1

    @pytest.mark.anyio
    async def test_audit_log_is_verifiable(self, audit_dir: Path) -> None:
        """The saved audit log should pass integrity verification."""
        from agentguard.audit.log import AuditLog
        from agentguard.mcp.server import create_server

        app = create_server(audit_dir=str(audit_dir))
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
                    await session.call_tool("shell_execute", {"command": "echo one"})
                    await session.call_tool("shell_execute", {"command": "echo two"})
                    tg.cancel_scope.cancel()

            tg.start_soon(run_server)
            tg.start_soon(run_client)

        jsonl_files = list(audit_dir.glob("*.jsonl"))
        assert len(jsonl_files) >= 1
        log = AuditLog.load(jsonl_files[0], session_id="verify")
        assert log.verify()
        assert len(log.entries) >= 2


# ===========================================================================
# Test: Server configuration
# ===========================================================================


class TestServerConfiguration:
    """Test server configuration and initialization."""

    @pytest.mark.anyio
    async def test_status_tool_shows_loaded_policies(self, policy_dir: Path) -> None:
        """agentguard_status should report loaded policies."""

        async def check(session: ClientSession) -> None:
            result = await session.call_tool("agentguard_status", {})
            assert not result.isError
            assert "no-force-push" in result.content[0].text  # type: ignore[union-attr]

        await with_server(check, policy_dir=policy_dir)

    @pytest.mark.anyio
    async def test_status_tool_shows_session_info(self) -> None:
        """agentguard_status should report the actor name."""

        async def check(session: ClientSession) -> None:
            result = await session.call_tool("agentguard_status", {})
            text = result.content[0].text  # type: ignore[union-attr]
            assert "status-test-agent" in text

        await with_server(check, actor="status-test-agent")

    @pytest.mark.anyio
    async def test_status_tool_shows_no_policies_when_empty(self) -> None:
        """agentguard_status with no policies should indicate that."""

        async def check(session: ClientSession) -> None:
            result = await session.call_tool("agentguard_status", {})
            text = result.content[0].text  # type: ignore[union-attr]
            assert "0" in text or "no policies" in text.lower()

        await with_server(check)

    def test_create_server_with_nonexistent_policy_dir(self, tmp_path: Path) -> None:
        """Server should raise if policy_dir doesn't exist."""
        from agentguard.mcp.server import create_server

        nonexistent = tmp_path / "does_not_exist"
        with pytest.raises((ValueError, FileNotFoundError)):
            create_server(policy_dir=str(nonexistent))

    @pytest.mark.anyio
    async def test_multiple_policy_files_loaded(self, tmp_path: Path) -> None:
        """Server should load all YAML files from the policy directory."""
        d = tmp_path / "multi_policies"
        d.mkdir()
        (d / "policy-a.yaml").write_text(
            "name: policy-a\n"
            "description: Test A\n"
            "rules:\n"
            "  - action: shell_execute\n"
            "    deny:\n"
            "      - pattern: 'rm -rf /'\n"
            "    severity: critical\n"
        )
        (d / "policy-b.yaml").write_text(
            "name: policy-b\n"
            "description: Test B\n"
            "rules:\n"
            "  - action: shell_execute\n"
            "    deny:\n"
            "      - pattern: 'DROP DATABASE'\n"
            "    severity: critical\n"
        )

        async def check(session: ClientSession) -> None:
            result = await session.call_tool("agentguard_status", {})
            text = result.content[0].text  # type: ignore[union-attr]
            assert "policy-a" in text
            assert "policy-b" in text

        await with_server(check, policy_dir=d)


# ===========================================================================
# Test: Audit query tool
# ===========================================================================


class TestAuditQueryTool:
    """Test the agentguard_audit_query tool."""

    @pytest.mark.anyio
    async def test_query_by_action(self, audit_dir: Path, tmp_path: Path) -> None:
        """Should filter audit entries by action type."""

        async def check(session: ClientSession) -> None:
            await session.call_tool("shell_execute", {"command": "echo test"})
            target = tmp_path / "querytest.txt"
            await session.call_tool(
                "file_write",
                {"path": str(target), "content": "x"},
            )
            result = await session.call_tool(
                "agentguard_audit_query", {"action": "file_write"}
            )
            text = result.content[0].text  # type: ignore[union-attr]
            assert "file_write" in text

        await with_server(check, audit_dir=audit_dir)

    @pytest.mark.anyio
    async def test_query_by_result(self, policy_dir: Path, audit_dir: Path) -> None:
        """Should filter audit entries by result."""

        async def check(session: ClientSession) -> None:
            await session.call_tool("shell_execute", {"command": "echo ok"})
            await session.call_tool(
                "shell_execute",
                {"command": "git push --force origin main"},
            )
            result = await session.call_tool(
                "agentguard_audit_query", {"result": "denied"}
            )
            text = result.content[0].text  # type: ignore[union-attr]
            assert "denied" in text

        await with_server(check, policy_dir=policy_dir, audit_dir=audit_dir)

    @pytest.mark.anyio
    async def test_query_empty_log(self) -> None:
        """Query on empty log should return empty / no entries message."""

        async def check(session: ClientSession) -> None:
            result = await session.call_tool("agentguard_audit_query", {})
            text = result.content[0].text  # type: ignore[union-attr]
            assert "0" in text or "no entries" in text.lower() or "[]" in text

        await with_server(check)


# ===========================================================================
# Test: Auto-discovery in MCP server
# ===========================================================================


class TestMCPAutoDiscovery:
    """Test that the MCP server supports auto_discover parameter."""

    @pytest.mark.anyio
    async def test_auto_discover_loads_project_policies(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Server with auto_discover=True should load project-level policies."""
        monkeypatch.chdir(tmp_path)
        monkeypatch.delenv("AGENTGUARD_POLICY_DIR", raising=False)

        project_dir = tmp_path / ".agentguard" / "policies"
        project_dir.mkdir(parents=True)
        (project_dir / "block-rm.yaml").write_text(
            "name: block-rm\n"
            "description: Block rm commands\n"
            "rules:\n"
            "  - action: shell_execute\n"
            "    deny:\n"
            "      - pattern: '\\brm\\b'\n"
            "    severity: critical\n"
        )

        async def check(session: ClientSession) -> None:
            result = await session.call_tool("agentguard_status", {})
            text = result.content[0].text  # type: ignore[union-attr]
            assert "block-rm" in text

        await with_server_auto_discover(check)

    @pytest.mark.anyio
    async def test_auto_discover_false_skips_project_policies(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """auto_discover=False (default) skips project policies."""
        monkeypatch.chdir(tmp_path)
        monkeypatch.delenv("AGENTGUARD_POLICY_DIR", raising=False)

        project_dir = tmp_path / ".agentguard" / "policies"
        project_dir.mkdir(parents=True)
        (project_dir / "block-rm.yaml").write_text(
            "name: block-rm\n"
            "description: Block rm commands\n"
            "rules:\n"
            "  - action: shell_execute\n"
            "    deny:\n"
            "      - pattern: '\\brm\\b'\n"
            "    severity: critical\n"
        )

        async def check(session: ClientSession) -> None:
            result = await session.call_tool("agentguard_status", {})
            text = result.content[0].text  # type: ignore[union-attr]
            assert "block-rm" not in text

        # Default (no auto_discover) — should NOT load project policies
        await with_server(check)


async def with_server_auto_discover(
    fn: Any,
    *,
    audit_dir: Path | None = None,
    actor: str = "test-agent",
) -> None:
    """Like with_server but with auto_discover=True."""
    from agentguard.mcp.server import create_server

    app = create_server(
        audit_dir=str(audit_dir) if audit_dir else None,
        actor=actor,
        auto_discover=True,
    )

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
# Test: Trust query MCP tool
# ===========================================================================


class TestTrustQueryTool:
    """Test the agentguard_trust_query MCP tool."""

    @pytest.mark.anyio
    async def test_query_empty_registry(self, tmp_path: Path) -> None:
        """Querying an empty registry should return zero servers."""
        reg_file = str(tmp_path / "trust.yaml")

        async def check(session: ClientSession) -> None:
            result = await session.call_tool("agentguard_trust_query", {})
            import json

            data = json.loads(result.content[0].text)
            assert data["count"] == 0
            assert data["servers"] == []

        await with_server(check, trust_registry=reg_file)

    @pytest.mark.anyio
    async def test_query_list_all(self, tmp_path: Path) -> None:
        """Listing all entries should return every registered server."""
        from agentguard.trust.registry import TrustRegistry

        reg_file = tmp_path / "trust.yaml"
        registry = TrustRegistry(path=reg_file)
        registry.add("server-a", "trusted")
        registry.add("server-b", "restricted")

        async def check(session: ClientSession) -> None:
            result = await session.call_tool("agentguard_trust_query", {})
            import json

            data = json.loads(result.content[0].text)
            assert data["count"] == 2
            names = {s["server_name"] for s in data["servers"]}
            assert names == {"server-a", "server-b"}

        await with_server(check, trust_registry=str(reg_file))

    @pytest.mark.anyio
    async def test_query_by_server_name(self, tmp_path: Path) -> None:
        """Looking up a specific server should return its entry."""
        from agentguard.trust.registry import TrustRegistry

        reg_file = tmp_path / "trust.yaml"
        registry = TrustRegistry(path=reg_file)
        registry.add("my-server", "trusted", notes="test note")

        async def check(session: ClientSession) -> None:
            result = await session.call_tool(
                "agentguard_trust_query", {"server_name": "my-server"}
            )
            import json

            data = json.loads(result.content[0].text)
            assert data["server_name"] == "my-server"
            assert data["trust_level"] == "trusted"
            assert data["notes"] == "test note"

        await with_server(check, trust_registry=str(reg_file))

    @pytest.mark.anyio
    async def test_query_server_not_found(self, tmp_path: Path) -> None:
        """Looking up a nonexistent server should return an error."""
        reg_file = str(tmp_path / "trust.yaml")

        async def check(session: ClientSession) -> None:
            result = await session.call_tool(
                "agentguard_trust_query", {"server_name": "no-such-server"}
            )
            import json

            data = json.loads(result.content[0].text)
            assert "error" in data
            assert "no-such-server" in data["error"]

        await with_server(check, trust_registry=reg_file)

    @pytest.mark.anyio
    async def test_query_filter_by_trust_level(self, tmp_path: Path) -> None:
        """Filtering by trust_level should return only matching servers."""
        from agentguard.trust.registry import TrustRegistry

        reg_file = tmp_path / "trust.yaml"
        registry = TrustRegistry(path=reg_file)
        registry.add("trusted-srv", "trusted")
        registry.add("restricted-srv", "restricted")
        registry.add("untrusted-srv", "untrusted")

        async def check(session: ClientSession) -> None:
            result = await session.call_tool(
                "agentguard_trust_query", {"trust_level": "restricted"}
            )
            import json

            data = json.loads(result.content[0].text)
            assert data["count"] == 1
            assert data["servers"][0]["server_name"] == "restricted-srv"
            assert data["servers"][0]["trust_level"] == "restricted"

        await with_server(check, trust_registry=str(reg_file))

    @pytest.mark.anyio
    async def test_query_handles_corrupted_registry(self, tmp_path: Path) -> None:
        """Trust query should return an error for a corrupted registry file."""
        reg_file = tmp_path / "trust.yaml"
        reg_file.write_text("not: [valid: yaml: {{{{")

        async def check(session: ClientSession) -> None:
            result = await session.call_tool("agentguard_trust_query", {})
            import json

            data = json.loads(result.content[0].text)
            assert "error" in data

        await with_server(check, trust_registry=str(reg_file))

    @pytest.mark.anyio
    @pytest.mark.skipif(
        hasattr(__import__("os"), "getuid") and __import__("os").getuid() == 0,
        reason="root ignores file permissions — chmod(0o000) has no effect",
    )
    async def test_query_handles_unreadable_registry(self, tmp_path: Path) -> None:
        """Trust query returns an error when the registry file is unreadable.

        Verifies the narrowed exception handling (#72) still catches
        OSError from permission-denied files.
        """
        reg_file = tmp_path / "trust.yaml"
        reg_file.write_text("version: 1\nservers: {}")
        reg_file.chmod(0o000)

        async def check(session: ClientSession) -> None:
            result = await session.call_tool("agentguard_trust_query", {})
            import json

            data = json.loads(result.content[0].text)
            assert "error" in data
            assert "Cannot load trust registry" in data["error"]

        try:
            await with_server(check, trust_registry=str(reg_file))
        finally:
            reg_file.chmod(0o644)

    @pytest.mark.anyio
    async def test_query_handles_invalid_trust_level_in_registry(
        self, tmp_path: Path
    ) -> None:
        """Trust query returns an error for invalid trust level values.

        A registry file with bogus trust_level values should be caught
        by the narrowed exception handling (#72).
        """
        reg_file = tmp_path / "trust.yaml"
        reg_file.write_text(
            "version: 1\n"
            "servers:\n"
            "  bad-server:\n"
            "    server_name: bad-server\n"
            "    trust_level: bogus_level\n"
            "    added_at: '2025-01-01T00:00:00+00:00'\n"
            "    updated_at: '2025-01-01T00:00:00+00:00'\n"
        )

        async def check(session: ClientSession) -> None:
            result = await session.call_tool("agentguard_trust_query", {})
            import json

            data = json.loads(result.content[0].text)
            assert "error" in data

        await with_server(check, trust_registry=str(reg_file))


# ===========================================================================
# Test: Scan package MCP tool
# ===========================================================================
# ===========================================================================


class TestScanPackageTool:
    """Test the agentguard_scan_package MCP tool."""

    @pytest.mark.anyio
    async def test_scan_tool_has_expected_params(self) -> None:
        """agentguard_scan_package should accept path and min_severity."""

        async def check(session: ClientSession) -> None:
            tools_resp = await session.list_tools()
            scan = next(
                t for t in tools_resp.tools if t.name == "agentguard_scan_package"
            )
            props = scan.inputSchema.get("properties", {})
            assert "path" in props
            assert "min_severity" in props

        await with_server(check)

    @pytest.mark.anyio
    async def test_scan_clean_package(self, tmp_path: Path) -> None:
        """Scanning a clean directory should return zero findings."""
        pkg = tmp_path / "clean_pkg"
        pkg.mkdir()
        (pkg / "main.py").write_text("x = 1\n")

        async def check(session: ClientSession) -> None:
            result = await session.call_tool(
                "agentguard_scan_package", {"path": str(pkg)}
            )
            import json

            data = json.loads(result.content[0].text)
            assert data["finding_count"] == 0
            assert data["files_scanned"] >= 1

        await with_server(check)

    @pytest.mark.anyio
    async def test_scan_with_findings(self, tmp_path: Path) -> None:
        """Scanning code with eval() should produce findings."""
        pkg = tmp_path / "bad_pkg"
        pkg.mkdir()
        (pkg / "evil.py").write_text("result = eval(\n")

        async def check(session: ClientSession) -> None:
            result = await session.call_tool(
                "agentguard_scan_package", {"path": str(pkg)}
            )
            import json

            data = json.loads(result.content[0].text)
            assert data["finding_count"] >= 1

        await with_server(check)

    @pytest.mark.anyio
    async def test_scan_missing_path(self) -> None:
        """Scanning a nonexistent path should return an error."""

        async def check(session: ClientSession) -> None:
            result = await session.call_tool(
                "agentguard_scan_package",
                {"path": "/nonexistent/xyz/pkg"},
            )
            import json

            data = json.loads(result.content[0].text)
            assert "error" in data

        await with_server(check)

    @pytest.mark.anyio
    async def test_scan_min_severity_filter(self, tmp_path: Path) -> None:
        """min_severity should filter out lower-severity findings."""
        pkg = tmp_path / "filter_pkg"
        pkg.mkdir()
        # base64.b64encode is MEDIUM severity
        (pkg / "encode.py").write_text("base64.b64encode(\n")

        async def check(session: ClientSession) -> None:
            # With no filter, should find something
            r1 = await session.call_tool("agentguard_scan_package", {"path": str(pkg)})
            import json

            d1 = json.loads(r1.content[0].text)

            # With critical filter, MEDIUM findings should be excluded
            r2 = await session.call_tool(
                "agentguard_scan_package",
                {"path": str(pkg), "min_severity": "critical"},
            )
            d2 = json.loads(r2.content[0].text)
            assert d2["finding_count"] <= d1["finding_count"]

        await with_server(check)
