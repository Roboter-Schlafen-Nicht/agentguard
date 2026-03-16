"""E2E tests: OpenCode integration workflow (SG-10).

Tests AgentGuard deployed as an OpenCode MCP sidecar in the actual
configuration used by RSN projects.  The MCP server is started with
a preset, auto-discover enabled, and an audit directory — exactly as
configured in a real opencode.json.

Test matrix:
  SG-10.1  OpenCode loads all 11 AgentGuard MCP tools on startup
  SG-10.2  Agent can read/write files through AgentGuard tools
  SG-10.3  Agent can run shell commands through AgentGuard
  SG-10.4  Policy blocks agent from committing secrets
  SG-10.5  RSN project-local policies enforced via auto-discover
  SG-10.6  Audit log accumulates across agent session
  SG-10.7  Agent status tool returns server state
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

import pytest

from tests.e2e.conftest import _get_text, _with_server

if TYPE_CHECKING:
    from pathlib import Path

    from mcp import ClientSession


# ---------------------------------------------------------------------------
# Expected tool names
# ---------------------------------------------------------------------------

#: The 12 MCP tools that AgentGuard registers.
EXPECTED_TOOLS: set[str] = {
    "shell_execute",
    "file_read",
    "file_write",
    "file_edit",
    "file_glob",
    "file_grep",
    "file_list",
    "web_fetch_js",
    "agentguard_status",
    "agentguard_audit_query",
    "agentguard_scan_package",
    "agentguard_trust_query",
}


# ---------------------------------------------------------------------------
# Inline RSN policy for auto-discover test (SG-10.5)
# ---------------------------------------------------------------------------

_RSN_NO_PRIVATE_COMMIT = """\
name: rsn-no-private-commit
description: Prevent staging private/ directory contents in git
rules:
  - action: shell_command
    description: Block git add of anything under private/ directories
    deny:
      - pattern: 'git\\s+add\\s+.*\\bprivate/'
    severity: critical
"""


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def auto_discover_policy_dir(tmp_path: Path) -> Path:
    """Create a .agentguard/policies/ directory with an RSN policy.

    Simulates the project-local auto-discover directory that real RSN
    projects have.  Returns the *project root* (parent of .agentguard/).
    """
    project_root = tmp_path / "project"
    project_root.mkdir()
    ag_dir = project_root / ".agentguard" / "policies"
    ag_dir.mkdir(parents=True)
    (ag_dir / "rsn-no-private-commit.yaml").write_text(_RSN_NO_PRIVATE_COMMIT)
    return project_root


# ===========================================================================
# SG-10 Tests: OpenCode Integration — Real Agent Workflow
# ===========================================================================


class TestToolDiscovery:
    """SG-10.1: OpenCode loads all 11 AgentGuard MCP tools on startup."""

    @pytest.mark.anyio()
    async def test_sg_10_1_all_tools_available(self, audit_dir: Path) -> None:
        """All 11 AgentGuard tools are listed by the MCP server."""

        async def check(session: ClientSession) -> None:
            tools_result = await session.list_tools()
            tool_names = {t.name for t in tools_result.tools}
            missing = EXPECTED_TOOLS - tool_names
            assert not missing, f"Missing tools: {missing}"

        await _with_server(
            check, audit_dir=audit_dir, preset="permissive", actor="opencode-agent"
        )

    @pytest.mark.anyio()
    async def test_sg_10_1_no_unexpected_tools(self, audit_dir: Path) -> None:
        """Only the expected 11 tools are registered — no extras."""

        async def check(session: ClientSession) -> None:
            tools_result = await session.list_tools()
            tool_names = {t.name for t in tools_result.tools}
            extra = tool_names - EXPECTED_TOOLS
            assert not extra, f"Unexpected extra tools: {extra}"

        await _with_server(
            check, audit_dir=audit_dir, preset="permissive", actor="opencode-agent"
        )

    @pytest.mark.anyio()
    async def test_sg_10_1_tool_count_is_12(self, audit_dir: Path) -> None:
        """Exactly 12 tools are available."""

        async def check(session: ClientSession) -> None:
            tools_result = await session.list_tools()
            assert len(tools_result.tools) == 12, (
                f"Expected 12 tools, got {len(tools_result.tools)}: "
                f"{[t.name for t in tools_result.tools]}"
            )

        await _with_server(
            check, audit_dir=audit_dir, preset="permissive", actor="opencode-agent"
        )


class TestFileWorkflow:
    """SG-10.2: Agent can read/write files through AgentGuard tools."""

    @pytest.mark.anyio()
    async def test_sg_10_2_write_and_read_file(
        self, tmp_path: Path, audit_dir: Path
    ) -> None:
        """Write a file via file_write, then read it via file_read."""
        target = tmp_path / "hello.py"

        async def check(session: ClientSession) -> None:
            # Write a file — simulating an agent creating code
            write_result = await session.call_tool(
                "file_write",
                {
                    "path": str(target),
                    "content": 'def hello():\n    return "Hello, world!"\n',
                },
            )
            assert not write_result.isError, (
                f"file_write failed: {_get_text(write_result)}"
            )

            # Read the file back
            read_result = await session.call_tool(
                "file_read",
                {"path": str(target)},
            )
            assert not read_result.isError, (
                f"file_read failed: {_get_text(read_result)}"
            )
            assert "def hello()" in _get_text(read_result)
            assert "Hello, world!" in _get_text(read_result)

        await _with_server(
            check, audit_dir=audit_dir, preset="permissive", actor="opencode-agent"
        )

        # Verify file exists on disk
        assert target.exists()
        assert "def hello()" in target.read_text()

    @pytest.mark.anyio()
    async def test_sg_10_2_file_operations_audited(
        self, tmp_path: Path, audit_dir: Path
    ) -> None:
        """Both file_write and file_read are recorded in the audit log."""
        target = tmp_path / "audited.txt"

        async def check(session: ClientSession) -> None:
            await session.call_tool(
                "file_write",
                {"path": str(target), "content": "audit test content\n"},
            )
            await session.call_tool(
                "file_read",
                {"path": str(target)},
            )

            # Query audit log for file operations
            write_result = await session.call_tool(
                "agentguard_audit_query",
                {"action": "file_write"},
            )
            write_entries = json.loads(_get_text(write_result))
            assert len(write_entries) == 1
            assert write_entries[-1]["result"] == "allowed"

            read_result = await session.call_tool(
                "agentguard_audit_query",
                {"action": "file_read"},
            )
            read_entries = json.loads(_get_text(read_result))
            assert len(read_entries) == 1
            assert read_entries[-1]["result"] == "allowed"

        await _with_server(
            check, audit_dir=audit_dir, preset="permissive", actor="opencode-agent"
        )


class TestShellWorkflow:
    """SG-10.3: Agent can run shell commands through AgentGuard."""

    @pytest.mark.anyio()
    async def test_sg_10_3_shell_command_execution(self, audit_dir: Path) -> None:
        """Shell command executes and returns output."""

        async def check(session: ClientSession) -> None:
            result = await session.call_tool(
                "shell_execute",
                {"command": "echo 'agent running'"},
            )
            assert not result.isError, f"shell_execute failed: {_get_text(result)}"
            assert "agent running" in _get_text(result)

        await _with_server(
            check, audit_dir=audit_dir, preset="permissive", actor="opencode-agent"
        )

    @pytest.mark.anyio()
    async def test_sg_10_3_shell_command_audited(self, audit_dir: Path) -> None:
        """Shell commands are recorded in the audit log."""

        async def check(session: ClientSession) -> None:
            await session.call_tool(
                "shell_execute",
                {"command": "python3 --version"},
            )

            result = await session.call_tool(
                "agentguard_audit_query",
                {"action": "shell_execute"},
            )
            entries = json.loads(_get_text(result))
            assert len(entries) == 1
            assert entries[-1]["result"] == "allowed"
            assert "python3 --version" in entries[-1]["target"]

        await _with_server(
            check, audit_dir=audit_dir, preset="permissive", actor="opencode-agent"
        )


class TestPolicyEnforcement:
    """SG-10.4: Policy blocks agent from committing secrets."""

    @pytest.mark.anyio()
    async def test_sg_10_4_secret_in_file_write_denied(
        self, tmp_path: Path, audit_dir: Path
    ) -> None:
        """Writing a file containing an API key is denied by policy."""
        target = tmp_path / "config.py"

        async def check(session: ClientSession) -> None:
            result = await session.call_tool(
                "file_write",
                {
                    "path": str(target),
                    "content": (
                        "# Configuration\n"
                        "AWS_SECRET_ACCESS_KEY="
                        "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
                    ),
                },
            )
            assert result.isError, "Expected denial but tool succeeded"
            assert "denied by policy" in _get_text(result)

        await _with_server(
            check, audit_dir=audit_dir, preset="balanced", actor="opencode-agent"
        )

        # File must NOT exist on disk
        assert not target.exists()

    @pytest.mark.anyio()
    async def test_sg_10_4_denial_recorded_in_audit(
        self, tmp_path: Path, audit_dir: Path
    ) -> None:
        """Policy denial is recorded as 'denied' in the audit log."""
        target = tmp_path / "secrets.env"

        async def check(session: ClientSession) -> None:
            await session.call_tool(
                "file_write",
                {
                    "path": str(target),
                    "content": (
                        "AWS_SECRET_ACCESS_KEY="
                        "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
                    ),
                },
            )

            result = await session.call_tool(
                "agentguard_audit_query",
                {"result": "denied"},
            )
            denied_entries = json.loads(_get_text(result))
            assert len(denied_entries) == 1
            assert denied_entries[-1]["action"] == "file_write"

        await _with_server(
            check, audit_dir=audit_dir, preset="balanced", actor="opencode-agent"
        )


class TestAutoDiscover:
    """SG-10.5: RSN project-local policies enforced via auto-discover."""

    @pytest.mark.anyio()
    async def test_sg_10_5_project_local_policy_blocks_command(
        self,
        auto_discover_policy_dir: Path,
        audit_dir: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A project-local RSN policy blocks a shell command."""
        # auto_discover looks at CWD/.agentguard/policies/
        monkeypatch.chdir(str(auto_discover_policy_dir))

        async def check(session: ClientSession) -> None:
            result = await session.call_tool(
                "shell_execute",
                {"command": "git add private/secrets.txt"},
            )
            assert result.isError, "Expected denial by rsn-no-private-commit policy"
            assert "denied by policy" in _get_text(result)

        await _with_server(
            check,
            audit_dir=audit_dir,
            preset="permissive",
            actor="opencode-agent",
            auto_discover=True,
        )

    @pytest.mark.anyio()
    async def test_sg_10_5_auto_discover_combines_with_preset(
        self,
        auto_discover_policy_dir: Path,
        audit_dir: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Auto-discovered policies work alongside preset policies."""
        monkeypatch.chdir(str(auto_discover_policy_dir))

        async def check(session: ClientSession) -> None:
            # Preset permissive still blocks force-push
            force_push = await session.call_tool(
                "shell_execute",
                {"command": "git push --force origin main"},
            )
            assert force_push.isError, "force-push should be denied by preset"

            # Auto-discovered policy blocks private/ staging
            private_add = await session.call_tool(
                "shell_execute",
                {"command": "git add private/data.yaml"},
            )
            assert private_add.isError, (
                "private/ staging should be denied by auto-discover"
            )

            # Clean commands still allowed
            echo_result = await session.call_tool(
                "shell_execute",
                {"command": "echo both-sources-active"},
            )
            assert not echo_result.isError

        await _with_server(
            check,
            audit_dir=audit_dir,
            preset="permissive",
            actor="opencode-agent",
            auto_discover=True,
        )


class TestAuditAccumulation:
    """SG-10.6: Audit log accumulates across agent session."""

    @pytest.mark.anyio()
    async def test_sg_10_6_multi_step_session_audit(
        self, tmp_path: Path, audit_dir: Path
    ) -> None:
        """A multi-step agent session produces a valid audit trail."""
        target = tmp_path / "workflow.py"

        async def check(session: ClientSession) -> None:
            # Step 1: Write a file
            await session.call_tool(
                "file_write",
                {
                    "path": str(target),
                    "content": "def greet(name):\n    return f'Hello, {name}'\n",
                },
            )

            # Step 2: Read the file
            await session.call_tool(
                "file_read",
                {"path": str(target)},
            )

            # Step 3: Edit the file
            await session.call_tool(
                "file_edit",
                {
                    "path": str(target),
                    "old_string": "Hello, {name}",
                    "new_string": "Hi, {name}!",
                },
            )

            # Step 4: Run a test
            await session.call_tool(
                "shell_execute",
                {"command": "echo tests-pass"},
            )

            # Step 5: Verify audit has all entries
            result = await session.call_tool(
                "agentguard_audit_query",
                {},
            )
            entries = json.loads(_get_text(result))
            # 4 tool calls above; audit_query does not record itself
            assert len(entries) == 4, (
                f"Expected exactly 4 audit entries, got {len(entries)}"
            )

            # Verify chronological action sequence
            actions = [e["action"] for e in entries[:4]]
            assert actions == [
                "file_write",
                "file_read",
                "file_edit",
                "shell_execute",
            ]

        await _with_server(
            check, audit_dir=audit_dir, preset="permissive", actor="opencode-agent"
        )

    @pytest.mark.anyio()
    async def test_sg_10_6_hash_chain_valid_after_session(
        self, tmp_path: Path, audit_dir: Path
    ) -> None:
        """Hash chain verifies clean after a multi-step session."""
        from agentguard.audit.log import AuditLog

        target = tmp_path / "chain.txt"

        async def check(session: ClientSession) -> None:
            await session.call_tool(
                "file_write",
                {"path": str(target), "content": "step 1\n"},
            )
            await session.call_tool(
                "file_read",
                {"path": str(target)},
            )
            await session.call_tool(
                "shell_execute",
                {"command": "echo step-3"},
            )

        await _with_server(
            check, audit_dir=audit_dir, preset="permissive", actor="opencode-agent"
        )

        # Load persisted audit log and verify hash chain
        jsonl_files = list(audit_dir.glob("*.jsonl"))
        assert len(jsonl_files) == 1, f"Expected 1 JSONL file, found {len(jsonl_files)}"
        log = AuditLog.load(jsonl_files[0], session_id=jsonl_files[0].stem)
        assert len(log.entries) == 3
        assert log.verify(), "Hash chain verification failed"


class TestStatusTool:
    """SG-10.7: Agent status tool returns server state."""

    @pytest.mark.anyio()
    async def test_sg_10_7_status_returns_state(self, audit_dir: Path) -> None:
        """agentguard_status returns loaded policy count and actor."""

        async def check(session: ClientSession) -> None:
            result = await session.call_tool("agentguard_status", {})
            assert not result.isError, f"status failed: {_get_text(result)}"
            status = json.loads(_get_text(result))
            assert "session_id" in status
            assert status["session_id"].startswith("ag-")
            assert "actor" in status
            assert status["actor"] == "opencode-agent"
            assert "policies_loaded" in status
            assert "policy_names" in status
            # Permissive preset loads 3 policies
            assert status["policies_loaded"] == 3
            assert len(status["policy_names"]) == 3

        await _with_server(
            check, audit_dir=audit_dir, preset="permissive", actor="opencode-agent"
        )

    @pytest.mark.anyio()
    async def test_sg_10_7_status_reflects_preset_policies(
        self, audit_dir: Path
    ) -> None:
        """Status shows the correct policies for the configured preset."""

        async def check(session: ClientSession) -> None:
            result = await session.call_tool("agentguard_status", {})
            status = json.loads(_get_text(result))

            # Permissive preset includes these critical-only policies
            policy_names = status["policy_names"]
            assert "no-data-deletion" in policy_names
            assert "no-force-push" in policy_names
            assert "no-secret-in-prompt" in policy_names

        await _with_server(
            check, audit_dir=audit_dir, preset="permissive", actor="opencode-agent"
        )

    @pytest.mark.anyio()
    async def test_sg_10_7_status_shows_audit_count(self, audit_dir: Path) -> None:
        """Status audit_count increments after tool calls."""

        async def check(session: ClientSession) -> None:
            # Check initial state
            result = await session.call_tool("agentguard_status", {})
            status = json.loads(_get_text(result))
            initial_count = status.get("audit_entries", 0)

            # Perform some actions
            await session.call_tool(
                "shell_execute",
                {"command": "echo counting"},
            )
            await session.call_tool(
                "shell_execute",
                {"command": "echo more"},
            )

            # Check count has increased
            result2 = await session.call_tool("agentguard_status", {})
            status2 = json.loads(_get_text(result2))
            # 2 shell_execute calls = +2 (status does not record audit)
            assert status2.get("audit_entries", 0) > initial_count

        await _with_server(
            check, audit_dir=audit_dir, preset="permissive", actor="opencode-agent"
        )
