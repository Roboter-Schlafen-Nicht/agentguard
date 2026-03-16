"""E2E tests: MCP server endurance under sustained tool usage (SG-15).

Validates that AgentGuard's MCP server remains fully functional after
prolonged usage.  These tests reproduce the real-world failure where
MCP tools "disappear" during long-running sessions, making the agent
lose its capabilities.

Root causes under test:
  - Unbounded in-memory audit log growth (list vs deque)
  - Response time degradation as audit entries accumulate
  - Tool availability after hundreds of consecutive calls

Test matrix:
  SG-15.1  Tool availability persists after 500 mixed tool calls
  SG-15.2  Response time does not degrade beyond 3x over 500 calls
  SG-15.3  Audit log entry count matches tool call count
  SG-15.4  list_tools returns full set after sustained file_write
  SG-15.5  list_tools returns full set after sustained shell_execute
  SG-15.6  list_tools returns full set after sustained file_glob
  SG-15.7  Concurrent burst of 50 rapid-fire tool calls
  SG-15.8  Session remains healthy after 1000 audit entries
"""

from __future__ import annotations

import json
import time
from typing import TYPE_CHECKING

import pytest

from tests.e2e.conftest import _get_text, _with_server

if TYPE_CHECKING:
    from pathlib import Path

    from mcp import ClientSession


# ---------------------------------------------------------------------------
# Constants
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

#: Number of tool calls for the main endurance loop.
ENDURANCE_ITERATIONS = 500

#: How often to check tool availability during the endurance loop.
CHECK_INTERVAL = 50

#: Maximum allowed response time ratio (last batch / first batch).
MAX_DEGRADATION_FACTOR = 3.0


# ===========================================================================
# SG-15 Tests: MCP Server Endurance
# ===========================================================================


class TestToolAvailabilityEndurance:
    """SG-15.1: Tools remain available after sustained usage."""

    @pytest.mark.anyio()
    async def test_sg_15_1_tools_available_after_500_calls(
        self, tmp_path: Path, audit_dir: Path
    ) -> None:
        """All 12 tools remain available after 500 mixed tool calls."""
        target_dir = tmp_path / "workdir"
        target_dir.mkdir()

        async def check(session: ClientSession) -> None:
            # Verify initial tool availability
            tools = await session.list_tools()
            initial_names = {t.name for t in tools.tools}
            assert initial_names == EXPECTED_TOOLS, (
                f"Initial tools mismatch: {initial_names}"
            )

            # Run 500 mixed tool calls
            for i in range(ENDURANCE_ITERATIONS):
                call_type = i % 5
                if call_type == 0:
                    # file_write
                    f = target_dir / f"file_{i}.txt"
                    await session.call_tool(
                        "file_write",
                        {"path": str(f), "content": f"content {i}"},
                    )
                elif call_type == 1:
                    # file_read
                    f = target_dir / f"file_{i - 1}.txt"
                    await session.call_tool("file_read", {"path": str(f)})
                elif call_type == 2:
                    # file_list
                    await session.call_tool("file_list", {"path": str(target_dir)})
                elif call_type == 3:
                    # file_glob
                    await session.call_tool(
                        "file_glob",
                        {"pattern": "*.txt", "path": str(target_dir)},
                    )
                elif call_type == 4:
                    # agentguard_status
                    await session.call_tool("agentguard_status", {})

                # Periodically verify tool availability
                if (i + 1) % CHECK_INTERVAL == 0:
                    tools = await session.list_tools()
                    names = {t.name for t in tools.tools}
                    assert names == EXPECTED_TOOLS, (
                        f"Tools disappeared after {i + 1} calls! "
                        f"Missing: {EXPECTED_TOOLS - names}, "
                        f"Extra: {names - EXPECTED_TOOLS}"
                    )

            # Final verification
            tools = await session.list_tools()
            final_names = {t.name for t in tools.tools}
            assert final_names == EXPECTED_TOOLS, (
                f"Tools missing at end of endurance run: {EXPECTED_TOOLS - final_names}"
            )
            assert len(tools.tools) == 12

        await _with_server(check, audit_dir=audit_dir, preset="permissive")


class TestResponseTimeDegradation:
    """SG-15.2: Response time stays within acceptable bounds."""

    @pytest.mark.anyio()
    async def test_sg_15_2_no_excessive_degradation(
        self, tmp_path: Path, audit_dir: Path
    ) -> None:
        """Response time for tool calls does not degrade more than 3x.

        Measures average response time for the first 50 calls vs
        the last 50 calls.  A ratio above MAX_DEGRADATION_FACTOR
        indicates a performance regression (likely unbounded audit
        log growth).
        """
        target_dir = tmp_path / "workdir"
        target_dir.mkdir()

        async def check(session: ClientSession) -> None:
            early_times: list[float] = []
            late_times: list[float] = []

            for i in range(ENDURANCE_ITERATIONS):
                f = target_dir / f"perf_{i}.txt"

                start = time.monotonic()
                await session.call_tool(
                    "file_write",
                    {"path": str(f), "content": f"perf test {i}"},
                )
                elapsed = time.monotonic() - start

                if i < CHECK_INTERVAL:
                    early_times.append(elapsed)
                elif i >= ENDURANCE_ITERATIONS - CHECK_INTERVAL:
                    late_times.append(elapsed)

            early_avg = sum(early_times) / len(early_times)
            late_avg = sum(late_times) / len(late_times)

            # Guard against division by zero
            if early_avg > 0:
                ratio = late_avg / early_avg
                assert ratio <= MAX_DEGRADATION_FACTOR, (
                    f"Response time degraded {ratio:.1f}x "
                    f"(early avg: {early_avg:.4f}s, "
                    f"late avg: {late_avg:.4f}s). "
                    f"Max allowed: {MAX_DEGRADATION_FACTOR}x"
                )

        await _with_server(check, audit_dir=audit_dir, preset="permissive")


class TestAuditLogIntegrity:
    """SG-15.3 / SG-15.8: Audit log integrity under sustained load."""

    @pytest.mark.anyio()
    async def test_sg_15_3_audit_count_matches_calls(
        self, tmp_path: Path, audit_dir: Path
    ) -> None:
        """Audit log records every tool call — none are lost.

        After N file_write calls, the audit log should contain
        exactly N entries for the file_write action.
        """
        target_dir = tmp_path / "workdir"
        target_dir.mkdir()
        call_count = 200

        async def check(session: ClientSession) -> None:
            for i in range(call_count):
                f = target_dir / f"audit_{i}.txt"
                await session.call_tool(
                    "file_write",
                    {"path": str(f), "content": f"audit test {i}"},
                )

            # Query audit log for file_write entries
            result = await session.call_tool(
                "agentguard_audit_query",
                {"action": "file_write"},
            )
            text = _get_text(result)
            data = json.loads(text)
            assert len(data) == call_count, (
                f"Expected {call_count} audit entries for file_write, got {len(data)}"
            )

        await _with_server(check, audit_dir=audit_dir, preset="permissive")

    @pytest.mark.anyio()
    async def test_sg_15_8_healthy_after_1000_entries(
        self, tmp_path: Path, audit_dir: Path
    ) -> None:
        """Session remains healthy after accumulating 1000 audit entries.

        Performs 1000 tool calls (mix of types to diversify audit
        entries), then verifies the server still responds to status
        queries and tool listing.
        """
        target_dir = tmp_path / "workdir"
        target_dir.mkdir()

        async def check(session: ClientSession) -> None:
            for i in range(1000):
                if i % 2 == 0:
                    f = target_dir / f"stress_{i}.txt"
                    await session.call_tool(
                        "file_write",
                        {"path": str(f), "content": f"stress {i}"},
                    )
                else:
                    await session.call_tool("agentguard_status", {})

            # Server must still respond to status
            result = await session.call_tool("agentguard_status", {})
            text = _get_text(result)
            status = json.loads(text)
            assert "session_id" in status, (
                f"Status response missing session_id: {status}"
            )
            # Only file_write calls are audited (500 of 1000 total);
            # agentguard_status is a sidecar tool with no audit record.
            assert status["audit_entries"] >= 500, (
                f"Expected >=500 audit entries, got {status['audit_entries']}"
            )

            # All tools must still be available
            tools = await session.list_tools()
            names = {t.name for t in tools.tools}
            assert names == EXPECTED_TOOLS
            assert len(tools.tools) == 12

        await _with_server(check, audit_dir=audit_dir, preset="permissive")


class TestSustainedSingleToolEndurance:
    """SG-15.4/5/6: Single tool types under sustained use."""

    @pytest.mark.anyio()
    async def test_sg_15_4_tools_after_sustained_file_write(
        self, tmp_path: Path, audit_dir: Path
    ) -> None:
        """Tools remain after 300 consecutive file_write calls."""
        target_dir = tmp_path / "workdir"
        target_dir.mkdir()

        async def check(session: ClientSession) -> None:
            for i in range(300):
                f = target_dir / f"write_{i}.txt"
                await session.call_tool(
                    "file_write",
                    {"path": str(f), "content": f"sustained write {i}"},
                )

            tools = await session.list_tools()
            names = {t.name for t in tools.tools}
            assert names == EXPECTED_TOOLS

        await _with_server(check, audit_dir=audit_dir, preset="permissive")

    @pytest.mark.anyio()
    async def test_sg_15_5_tools_after_sustained_shell_execute(
        self, tmp_path: Path, audit_dir: Path
    ) -> None:
        """Tools remain after 300 consecutive shell_execute calls."""

        async def check(session: ClientSession) -> None:
            for i in range(300):
                await session.call_tool(
                    "shell_execute", {"command": f"echo iteration_{i}"}
                )

            tools = await session.list_tools()
            names = {t.name for t in tools.tools}
            assert names == EXPECTED_TOOLS

        await _with_server(check, audit_dir=audit_dir, preset="permissive")

    @pytest.mark.anyio()
    async def test_sg_15_6_tools_after_sustained_file_glob(
        self, tmp_path: Path, audit_dir: Path
    ) -> None:
        """Tools remain after 300 consecutive file_glob calls."""
        target_dir = tmp_path / "workdir"
        target_dir.mkdir()
        # Create some files to glob
        for i in range(10):
            (target_dir / f"glob_{i}.txt").write_text(f"glob {i}")

        async def check(session: ClientSession) -> None:
            for _i in range(300):
                await session.call_tool(
                    "file_glob",
                    {"pattern": "*.txt", "path": str(target_dir)},
                )

            tools = await session.list_tools()
            names = {t.name for t in tools.tools}
            assert names == EXPECTED_TOOLS

        await _with_server(check, audit_dir=audit_dir, preset="permissive")


class TestRapidFireBurst:
    """SG-15.7: Rapid-fire burst of tool calls."""

    @pytest.mark.anyio()
    async def test_sg_15_7_rapid_fire_50_calls(
        self, tmp_path: Path, audit_dir: Path
    ) -> None:
        """50 tool calls as fast as possible — no gaps.

        Tests that the MCP server handles a burst without dropping
        tools or crashing.  This simulates an agent making many
        calls without waiting for human interaction.
        """
        target_dir = tmp_path / "workdir"
        target_dir.mkdir()

        async def check(session: ClientSession) -> None:
            # Verify before
            tools = await session.list_tools()
            assert len(tools.tools) == 12

            # Rapid-fire burst
            for i in range(50):
                f = target_dir / f"burst_{i}.txt"
                await session.call_tool(
                    "file_write",
                    {"path": str(f), "content": f"burst {i}"},
                )

            # Verify after
            tools = await session.list_tools()
            names = {t.name for t in tools.tools}
            assert names == EXPECTED_TOOLS
            assert len(tools.tools) == 12

            # Verify audit integrity
            result = await session.call_tool(
                "agentguard_audit_query",
                {"action": "file_write"},
            )
            text = _get_text(result)
            data = json.loads(text)
            assert len(data) == 50, f"Expected 50 audit entries, got {len(data)}"

        await _with_server(check, audit_dir=audit_dir, preset="permissive")
