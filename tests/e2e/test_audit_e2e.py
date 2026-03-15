"""E2E tests: Audit hash chain integrity and querying (SG-7).

Tests the audit system's tamper-evidence, persistence, and query
capabilities through the full MCP protocol via anyio memory streams.

Test matrix:
  SG-7.1  SHA-256 hash chain is valid after multiple actions
  SG-7.2  Tampered audit entry is detected by verify()
  SG-7.3  Query by action type returns matching entries only
  SG-7.4  Query by result filters allowed vs denied
  SG-7.5  Query by actor returns entries with correct actor
  SG-7.6  Entries persist to JSONL and survive server restart
  SG-7.7  agentguard_audit_query MCP tool returns entries
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

import pytest

from agentguard.audit.log import AuditLog
from tests.e2e.conftest import _get_text, _with_server

if TYPE_CHECKING:
    from pathlib import Path

    from mcp import ClientSession


def _load_audit_log(audit_dir: Path) -> AuditLog:
    """Load the single audit log file from the audit directory."""
    jsonl_files = list(audit_dir.glob("*.jsonl"))
    assert len(jsonl_files) == 1, f"Expected 1 JSONL file, found {len(jsonl_files)}"
    return AuditLog.load(jsonl_files[0], session_id=jsonl_files[0].stem)


# ===========================================================================
# SG-7 Tests: Audit hash chain integrity and querying
# ===========================================================================


class TestAuditHashChainValid:
    """SG-7.1: SHA-256 hash chain is valid after multiple actions."""

    @pytest.mark.anyio()
    async def test_sg_7_1_hash_chain_valid(self, audit_dir: Path) -> None:
        """Multiple MCP tool calls produce a valid hash chain."""

        async def check(session: ClientSession) -> None:
            # Execute several different actions to build the chain
            await session.call_tool(
                "shell_execute",
                {"command": "echo action-one"},
            )
            await session.call_tool(
                "file_read",
                {"path": "pyproject.toml"},
            )
            await session.call_tool(
                "shell_execute",
                {"command": "echo action-three"},
            )

        await _with_server(check, audit_dir=audit_dir, preset="permissive")

        log = _load_audit_log(audit_dir)
        assert len(log.entries) >= 3, (
            f"Expected at least 3 entries, got {len(log.entries)}"
        )
        assert log.verify(), "Hash chain verification failed"

        # First entry must have no previous hash
        assert log.entries[0].previous_hash is None
        # Subsequent entries must chain to the previous entry
        for i in range(1, len(log.entries)):
            assert log.entries[i].previous_hash == log.entries[i - 1].entry_hash


class TestAuditTamperDetection:
    """SG-7.2: Tampered audit entry is detected by verify()."""

    @pytest.mark.anyio()
    async def test_sg_7_2_tampered_entry_detected(
        self,
        audit_dir: Path,
    ) -> None:
        """Modifying a field in the JSONL file causes verify() to fail."""

        async def check(session: ClientSession) -> None:
            await session.call_tool(
                "shell_execute",
                {"command": "echo entry-one"},
            )
            await session.call_tool(
                "shell_execute",
                {"command": "echo entry-two"},
            )

        await _with_server(check, audit_dir=audit_dir, preset="permissive")

        # Tamper with the first entry in the JSONL file
        jsonl_files = list(audit_dir.glob("*.jsonl"))
        assert len(jsonl_files) == 1
        jsonl_path = jsonl_files[0]

        lines = jsonl_path.read_text(encoding="utf-8").strip().split("\n")
        assert len(lines) >= 2

        # Modify the action field of the first entry
        first_entry = json.loads(lines[0])
        first_entry["action"] = "TAMPERED_ACTION"
        lines[0] = json.dumps(first_entry, ensure_ascii=True)
        jsonl_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

        # Load and verify -- should detect tampering
        log = AuditLog.load(jsonl_path, session_id=jsonl_path.stem)
        assert not log.verify(), "verify() should return False for tampered log"


class TestAuditQueryByAction:
    """SG-7.3: Query by action type returns only matching entries."""

    @pytest.mark.anyio()
    async def test_sg_7_3_query_by_action(self, audit_dir: Path) -> None:
        """agentguard_audit_query with action filter returns matches."""

        async def check(session: ClientSession) -> None:
            # Mix different action types
            await session.call_tool(
                "shell_execute",
                {"command": "echo hello"},
            )
            await session.call_tool(
                "file_read",
                {"path": "pyproject.toml"},
            )
            await session.call_tool(
                "shell_execute",
                {"command": "echo world"},
            )

            # Query for file_read actions only
            result = await session.call_tool(
                "agentguard_audit_query",
                {"action": "file_read"},
            )
            assert not result.isError, f"Query failed: {_get_text(result)}"
            entries = json.loads(_get_text(result))
            assert len(entries) >= 1
            for entry in entries:
                assert entry["action"] == "file_read"

        await _with_server(check, audit_dir=audit_dir, preset="permissive")


class TestAuditQueryByResult:
    """SG-7.4: Query by result filters allowed vs denied."""

    @pytest.mark.anyio()
    async def test_sg_7_4_query_by_result(self, audit_dir: Path) -> None:
        """Query for denied entries returns only policy-blocked actions."""

        async def check(session: ClientSession) -> None:
            # Allowed action
            await session.call_tool(
                "shell_execute",
                {"command": "echo safe"},
            )
            # Denied action (no-force-push policy in permissive preset)
            await session.call_tool(
                "shell_execute",
                {"command": "git push --force origin main"},
            )

            # Query for denied entries
            result = await session.call_tool(
                "agentguard_audit_query",
                {"result": "denied"},
            )
            assert not result.isError, f"Query failed: {_get_text(result)}"
            entries = json.loads(_get_text(result))
            assert len(entries) >= 1
            for entry in entries:
                assert entry["result"] == "denied"

            # Query for allowed entries
            result_allowed = await session.call_tool(
                "agentguard_audit_query",
                {"result": "allowed"},
            )
            allowed_entries = json.loads(_get_text(result_allowed))
            assert len(allowed_entries) >= 1
            for entry in allowed_entries:
                assert entry["result"] == "allowed"

        await _with_server(check, audit_dir=audit_dir, preset="permissive")


class TestAuditQueryByActor:
    """SG-7.5: Query by actor returns entries with the correct actor."""

    @pytest.mark.anyio()
    async def test_sg_7_5_query_by_actor(self, audit_dir: Path) -> None:
        """All entries have the actor set at server creation time."""
        custom_actor = "custom-audit-agent"

        async def check(session: ClientSession) -> None:
            await session.call_tool(
                "shell_execute",
                {"command": "echo actor-test"},
            )
            await session.call_tool(
                "file_read",
                {"path": "pyproject.toml"},
            )

            # Query by actor
            result = await session.call_tool(
                "agentguard_audit_query",
                {"actor": custom_actor},
            )
            assert not result.isError, f"Query failed: {_get_text(result)}"
            entries = json.loads(_get_text(result))
            assert len(entries) >= 2
            for entry in entries:
                assert entry["actor"] == custom_actor

            # Query for a non-existent actor returns empty
            result_none = await session.call_tool(
                "agentguard_audit_query",
                {"actor": "nonexistent-actor"},
            )
            empty_entries = json.loads(_get_text(result_none))
            assert len(empty_entries) == 0

        await _with_server(
            check,
            audit_dir=audit_dir,
            preset="permissive",
            actor=custom_actor,
        )


class TestAuditPersistence:
    """SG-7.6: Entries persist to JSONL and survive server restart."""

    @pytest.mark.anyio()
    async def test_sg_7_6_entries_persist_across_restart(
        self,
        audit_dir: Path,
    ) -> None:
        """Entries written by one server session are loadable after it ends."""
        actions_recorded: list[str] = []

        async def check(session: ClientSession) -> None:
            cmds = [
                "echo persist-one",
                "echo persist-two",
                "echo persist-three",
            ]
            for cmd in cmds:
                await session.call_tool("shell_execute", {"command": cmd})
                actions_recorded.append(cmd)

        await _with_server(check, audit_dir=audit_dir, preset="permissive")

        # Server has stopped -- load entries from disk
        log = _load_audit_log(audit_dir)
        assert len(log.entries) >= len(actions_recorded)
        assert log.verify(), "Hash chain should be valid after reload"

        # Verify the persisted entries contain our commands
        targets = [e.target for e in log.entries]
        for cmd in actions_recorded:
            assert cmd in targets, f"Command '{cmd}' not found in persisted log"


class TestAuditMcpToolReturnsEntries:
    """SG-7.7: agentguard_audit_query MCP tool returns all entries."""

    @pytest.mark.anyio()
    async def test_sg_7_7_audit_tool_returns_entries(
        self,
        audit_dir: Path,
    ) -> None:
        """Calling agentguard_audit_query with no filters returns all."""

        async def check(session: ClientSession) -> None:
            # Generate some entries
            await session.call_tool(
                "shell_execute",
                {"command": "echo audit-one"},
            )
            await session.call_tool(
                "file_read",
                {"path": "pyproject.toml"},
            )

            # Query all entries (no filters)
            result = await session.call_tool(
                "agentguard_audit_query",
                {},
            )
            assert not result.isError, f"Query failed: {_get_text(result)}"
            entries = json.loads(_get_text(result))
            # At least the 2 actions we just performed
            assert len(entries) >= 2

            # Verify each entry has required fields
            required_fields = {
                "action",
                "actor",
                "target",
                "result",
                "timestamp",
                "previous_hash",
                "entry_hash",
            }
            for entry in entries:
                missing = required_fields - set(entry.keys())
                assert not missing, f"Entry missing fields: {missing}"

            # Verify hash chain structure in the response
            assert entries[0]["previous_hash"] is None
            for i in range(1, len(entries)):
                assert entries[i]["previous_hash"] == entries[i - 1]["entry_hash"]

        await _with_server(check, audit_dir=audit_dir, preset="permissive")
