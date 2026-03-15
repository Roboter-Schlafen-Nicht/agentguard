"""E2E tests: Error handling and edge cases (SG-13).

Tests graceful degradation under error conditions: missing files,
permission errors, timeouts, malformed inputs, and rapid sequential
calls.  These are the scenarios that cause production failures — not
the happy path.

Test matrix:
  SG-13.1  file_read on non-existent file returns error
  SG-13.2  file_write to read-only directory returns error
  SG-13.3  shell_execute with timeout — long-running command
  SG-13.4  file_edit with old_string not found in file
  SG-13.5  file_edit with multiple matches for old_string
  SG-13.6  Proxy handles malformed JSON request body
  SG-13.7  Proxy handles empty request body
  SG-13.8  MCP server handles rapid sequential tool calls
"""

from __future__ import annotations

import json
import os
import sys
from typing import TYPE_CHECKING

import httpx
import pytest

from tests.e2e.conftest import (
    _create_proxy,
    _get_text,
    _with_server,
)

if TYPE_CHECKING:
    from pathlib import Path

    from mcp import ClientSession

    from tests.e2e.conftest import MockUpstream


# ===========================================================================
# SG-13 Tests: Error Handling & Edge Cases
# ===========================================================================


class TestFileReadErrors:
    """SG-13.1: file_read on non-existent file returns error."""

    @pytest.mark.anyio()
    async def test_sg_13_1_nonexistent_file_returns_error(
        self, tmp_path: Path, audit_dir: Path
    ) -> None:
        """Reading a file that does not exist returns isError=True."""
        missing = tmp_path / "does_not_exist.txt"

        async def check(session: ClientSession) -> None:
            result = await session.call_tool(
                "file_read",
                {"path": str(missing)},
            )
            assert result.isError, "Expected error for non-existent file"
            assert "not found" in _get_text(result).lower()

        await _with_server(check, audit_dir=audit_dir)

    @pytest.mark.anyio()
    async def test_sg_13_1_nonexistent_file_audited(
        self, tmp_path: Path, audit_dir: Path
    ) -> None:
        """file_read error on missing file is recorded in the audit log."""
        missing = tmp_path / "ghost.txt"

        async def check(session: ClientSession) -> None:
            await session.call_tool(
                "file_read",
                {"path": str(missing)},
            )

            result = await session.call_tool(
                "agentguard_audit_query",
                {"action": "file_read"},
            )
            entries = json.loads(_get_text(result))
            assert len(entries) == 1
            assert entries[-1]["result"] == "error"

        await _with_server(check, audit_dir=audit_dir)


class TestFileWriteErrors:
    """SG-13.2: file_write to read-only directory returns error."""

    @pytest.mark.anyio()
    async def test_sg_13_2_readonly_dir_returns_error(
        self, tmp_path: Path, audit_dir: Path
    ) -> None:
        """Writing to a read-only directory returns an error."""
        if sys.platform == "win32":
            pytest.skip("Read-only directory test not reliable on Windows")
        if os.getuid() == 0:
            pytest.skip("Root ignores filesystem permissions")

        readonly_dir = tmp_path / "readonly"
        readonly_dir.mkdir()
        target = readonly_dir / "test.txt"
        os.chmod(readonly_dir, 0o444)

        try:

            async def check(session: ClientSession) -> None:
                result = await session.call_tool(
                    "file_write",
                    {"path": str(target), "content": "should fail\n"},
                )
                assert result.isError, "Expected error for read-only directory"
                text = _get_text(result).lower()
                assert "permission" in text or "denied" in text or "error" in text

            await _with_server(check, audit_dir=audit_dir)
        finally:
            os.chmod(readonly_dir, 0o755)

    @pytest.mark.anyio()
    async def test_sg_13_2_no_crash_on_permission_error(
        self, tmp_path: Path, audit_dir: Path
    ) -> None:
        """Server does not crash after a permission error — next call works."""
        if sys.platform == "win32":
            pytest.skip("Read-only directory test not reliable on Windows")
        if os.getuid() == 0:
            pytest.skip("Root ignores filesystem permissions")

        readonly_dir = tmp_path / "readonly2"
        readonly_dir.mkdir()
        target_bad = readonly_dir / "fail.txt"
        target_good = tmp_path / "success.txt"
        os.chmod(readonly_dir, 0o444)

        try:

            async def check(session: ClientSession) -> None:
                # First call fails
                r1 = await session.call_tool(
                    "file_write",
                    {"path": str(target_bad), "content": "fail\n"},
                )
                assert r1.isError

                # Second call to a writable location succeeds
                r2 = await session.call_tool(
                    "file_write",
                    {"path": str(target_good), "content": "ok\n"},
                )
                assert not r2.isError, f"Unexpected error: {_get_text(r2)}"

            await _with_server(check, audit_dir=audit_dir)
        finally:
            os.chmod(readonly_dir, 0o755)

        assert target_good.exists()
        assert target_good.read_text() == "ok\n"


class TestShellTimeout:
    """SG-13.3: shell_execute with timeout — long-running command."""

    @pytest.mark.anyio()
    async def test_sg_13_3_timeout_returns_error(self, audit_dir: Path) -> None:
        """A command exceeding the 30s timeout returns an error."""

        async def check(session: ClientSession) -> None:
            result = await session.call_tool(
                "shell_execute",
                {"command": "sleep 35"},
            )
            assert result.isError, "Expected timeout error"
            assert "timed out" in _get_text(result).lower()

        await _with_server(check, audit_dir=audit_dir)

    @pytest.mark.anyio()
    async def test_sg_13_3_timeout_audited(self, audit_dir: Path) -> None:
        """Timeout error is recorded in the audit log."""

        async def check(session: ClientSession) -> None:
            await session.call_tool(
                "shell_execute",
                {"command": "sleep 35"},
            )

            result = await session.call_tool(
                "agentguard_audit_query",
                {"action": "shell_execute"},
            )
            entries = json.loads(_get_text(result))
            assert len(entries) == 1
            assert entries[-1]["result"] == "error"

        await _with_server(check, audit_dir=audit_dir)

    @pytest.mark.anyio()
    async def test_sg_13_3_no_zombie_after_timeout(self, audit_dir: Path) -> None:
        """Server continues normally after a timeout — no zombie process."""

        async def check(session: ClientSession) -> None:
            # Trigger timeout
            await session.call_tool(
                "shell_execute",
                {"command": "sleep 35"},
            )

            # Next command should work fine
            result = await session.call_tool(
                "shell_execute",
                {"command": "echo alive"},
            )
            assert not result.isError, f"Unexpected error: {_get_text(result)}"
            assert "alive" in _get_text(result)

        await _with_server(check, audit_dir=audit_dir)


class TestFileEditErrors:
    """SG-13.4/5: file_edit with old_string not found / multiple matches."""

    @pytest.mark.anyio()
    async def test_sg_13_4_old_string_not_found(
        self, tmp_path: Path, audit_dir: Path
    ) -> None:
        """file_edit returns error when old_string is not in the file."""
        target = tmp_path / "edit_test.txt"
        target.write_text("Hello world\n")

        async def check(session: ClientSession) -> None:
            result = await session.call_tool(
                "file_edit",
                {
                    "path": str(target),
                    "old_string": "NONEXISTENT STRING",
                    "new_string": "replacement",
                },
            )
            assert result.isError, "Expected error for old_string not found"
            assert "not found" in _get_text(result).lower()

        await _with_server(check, audit_dir=audit_dir)

        # File should be unchanged
        assert target.read_text() == "Hello world\n"

    @pytest.mark.anyio()
    async def test_sg_13_4_old_string_not_found_audited(
        self, tmp_path: Path, audit_dir: Path
    ) -> None:
        """old_string-not-found error is recorded in audit."""
        target = tmp_path / "edit_audit.txt"
        target.write_text("original content\n")

        async def check(session: ClientSession) -> None:
            await session.call_tool(
                "file_edit",
                {
                    "path": str(target),
                    "old_string": "MISSING",
                    "new_string": "replaced",
                },
            )

            result = await session.call_tool(
                "agentguard_audit_query",
                {"action": "file_edit"},
            )
            entries = json.loads(_get_text(result))
            assert len(entries) == 1
            assert entries[-1]["result"] == "error"

        await _with_server(check, audit_dir=audit_dir)

    @pytest.mark.anyio()
    async def test_sg_13_5_multiple_matches(
        self, tmp_path: Path, audit_dir: Path
    ) -> None:
        """file_edit returns error when old_string matches multiple times."""
        target = tmp_path / "multi_match.txt"
        target.write_text("foo\nbar\nfoo\nbaz\nfoo\n")

        async def check(session: ClientSession) -> None:
            result = await session.call_tool(
                "file_edit",
                {
                    "path": str(target),
                    "old_string": "foo",
                    "new_string": "qux",
                },
            )
            assert result.isError, "Expected error for multiple matches"
            text = _get_text(result).lower()
            assert "match" in text

        await _with_server(check, audit_dir=audit_dir)

        # File should be unchanged
        assert target.read_text() == "foo\nbar\nfoo\nbaz\nfoo\n"

    @pytest.mark.anyio()
    async def test_sg_13_5_multiple_matches_suggests_replace_all(
        self, tmp_path: Path, audit_dir: Path
    ) -> None:
        """Error message suggests using replace_all for multiple matches."""
        target = tmp_path / "suggest_replace.txt"
        target.write_text("dup\ndup\n")

        async def check(session: ClientSession) -> None:
            result = await session.call_tool(
                "file_edit",
                {
                    "path": str(target),
                    "old_string": "dup",
                    "new_string": "unique",
                },
            )
            assert result.isError
            assert "replace_all" in _get_text(result)

        await _with_server(check, audit_dir=audit_dir)


class TestProxyMalformedInput:
    """SG-13.6/7: Proxy handles malformed and empty request bodies."""

    @pytest.mark.anyio()
    async def test_sg_13_6_malformed_json_no_crash(
        self, mock_upstream: MockUpstream, audit_dir: Path
    ) -> None:
        """Proxy does not crash on malformed JSON request body."""
        app = _create_proxy(mock_upstream, audit_dir)

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://testserver",
        ) as client:
            resp = await client.post(
                "/v1/chat/completions",
                content=b"{ this is not valid json !!!",
                headers={"content-type": "application/json"},
            )
            # Proxy should either forward (200) or return an error,
            # but must NOT crash (5xx due to unhandled exception)
            assert resp.status_code != 500

    @pytest.mark.anyio()
    async def test_sg_13_6_malformed_json_passes_through(
        self, mock_upstream: MockUpstream, audit_dir: Path
    ) -> None:
        """Malformed JSON is forwarded to upstream without scanning."""
        mock_upstream.set_response({"choices": [{"message": {"content": "ok"}}]})
        app = _create_proxy(mock_upstream, audit_dir, load_builtins=True)

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://testserver",
        ) as client:
            resp = await client.post(
                "/v1/chat/completions",
                content=b"not-json-at-all",
                headers={"content-type": "application/json"},
            )
            # Should pass through since scanning can't parse the body
            assert resp.status_code == 200

    @pytest.mark.anyio()
    async def test_sg_13_7_empty_body_no_crash(
        self, mock_upstream: MockUpstream, audit_dir: Path
    ) -> None:
        """Proxy does not crash on empty request body."""
        mock_upstream.set_response({"choices": [{"message": {"content": "ok"}}]})
        app = _create_proxy(mock_upstream, audit_dir)

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://testserver",
        ) as client:
            resp = await client.post(
                "/v1/chat/completions",
                content=b"",
                headers={"content-type": "application/json"},
            )
            assert resp.status_code != 500

    @pytest.mark.anyio()
    async def test_sg_13_7_empty_body_audited(
        self, mock_upstream: MockUpstream, audit_dir: Path
    ) -> None:
        """Empty-body request is recorded in the proxy audit log."""
        mock_upstream.set_response({"choices": [{"message": {"content": "ok"}}]})
        app = _create_proxy(mock_upstream, audit_dir)

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://testserver",
        ) as client:
            await client.post(
                "/v1/chat/completions",
                content=b"",
                headers={"content-type": "application/json"},
            )

        # Check audit log exists
        jsonl_files = list(audit_dir.glob("*.jsonl"))
        assert len(jsonl_files) == 1, "Expected audit log for empty-body request"


class TestRapidSequentialCalls:
    """SG-13.8: MCP server handles rapid sequential tool calls."""

    @pytest.mark.anyio()
    async def test_sg_13_8_fifty_rapid_calls_all_processed(
        self, tmp_path: Path, audit_dir: Path
    ) -> None:
        """50 rapid sequential MCP tool calls are all processed."""

        async def check(session: ClientSession) -> None:
            for i in range(50):
                result = await session.call_tool(
                    "shell_execute",
                    {"command": f"echo call-{i}"},
                )
                assert not result.isError, f"Call {i} failed: {_get_text(result)}"
                assert f"call-{i}" in _get_text(result)

        await _with_server(check, audit_dir=audit_dir)

    @pytest.mark.anyio()
    async def test_sg_13_8_audit_contains_all_entries(
        self, tmp_path: Path, audit_dir: Path
    ) -> None:
        """Audit log contains entries for all 50 rapid calls."""
        from agentguard.audit.log import AuditLog

        async def check(session: ClientSession) -> None:
            for i in range(50):
                await session.call_tool(
                    "shell_execute",
                    {"command": f"echo batch-{i}"},
                )

        await _with_server(check, audit_dir=audit_dir)

        # Verify audit log
        jsonl_files = list(audit_dir.glob("*.jsonl"))
        assert len(jsonl_files) == 1
        log = AuditLog.load(jsonl_files[0], session_id=jsonl_files[0].stem)
        shell_entries = [e for e in log.entries if e.action == "shell_execute"]
        assert len(shell_entries) == 50, (
            f"Expected 50 shell_execute entries, got {len(shell_entries)}"
        )

    @pytest.mark.anyio()
    async def test_sg_13_8_hash_chain_valid_after_burst(
        self, tmp_path: Path, audit_dir: Path
    ) -> None:
        """Hash chain is valid after 50 rapid sequential calls."""
        from agentguard.audit.log import AuditLog

        async def check(session: ClientSession) -> None:
            for i in range(50):
                await session.call_tool(
                    "shell_execute",
                    {"command": f"echo burst-{i}"},
                )

        await _with_server(check, audit_dir=audit_dir)

        jsonl_files = list(audit_dir.glob("*.jsonl"))
        assert len(jsonl_files) == 1
        log = AuditLog.load(jsonl_files[0], session_id=jsonl_files[0].stem)
        assert log.verify(), "Hash chain verification failed after 50 rapid calls"
