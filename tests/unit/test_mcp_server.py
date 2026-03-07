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
# Test: Server creation and tool listing
# ===========================================================================


class TestServerToolDefinitions:
    """Test that the MCP server exposes the expected tools."""

    @pytest.mark.anyio
    async def test_server_lists_tools(self) -> None:
        """Server should expose shell_execute, file_read, file_write,
        agentguard_status, and agentguard_audit_query tools."""

        async def check(session: ClientSession) -> None:
            tools_resp = await session.list_tools()
            tool_names = {t.name for t in tools_resp.tools}
            assert "shell_execute" in tool_names
            assert "file_read" in tool_names
            assert "file_write" in tool_names
            assert "agentguard_status" in tool_names
            assert "agentguard_audit_query" in tool_names

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
