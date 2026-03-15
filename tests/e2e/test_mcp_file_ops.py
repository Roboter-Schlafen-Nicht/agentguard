"""E2E tests: MCP file operations under policy (SG-1).

Tests file_write, file_edit, file_read, file_glob, file_grep, and
file_list MCP tools with policy enforcement using the full MCP
protocol via anyio memory streams.

Test matrix:
  SG-1.1  Secret blocked in file_write
  SG-1.2  Clean write allowed
  SG-1.3  Secret blocked in file_edit
  SG-1.4  Normal edit allowed
  SG-1.5  file_read audited
  SG-1.6  file_glob capped at 100
  SG-1.7  file_grep matches
  SG-1.8  file_list directory
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

import pytest

from tests.e2e.conftest import _with_server

if TYPE_CHECKING:
    from pathlib import Path

    from mcp import ClientSession


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def file_edit_secret_policy_dir(tmp_path: Path) -> Path:
    """Create a policy directory that blocks secrets in file_edit.

    The builtin no-secret-exposure policy only covers file_write.
    This fixture adds a policy covering file_edit as well.
    """
    d = tmp_path / "policies"
    d.mkdir(exist_ok=True)
    (d / "no-secret-in-edit.yaml").write_text(
        "name: no-secret-in-edit\n"
        "description: Block editing secrets into files\n"
        "rules:\n"
        "  - action: file_edit\n"
        "    deny:\n"
        "      - pattern: 'AWS_SECRET_ACCESS_KEY'\n"
        "      - pattern: 'API_KEY\\s*='\n"
        "      - pattern: 'sk-[a-zA-Z0-9]{20,}'\n"
        "    severity: critical\n"
    )
    return d


# ===========================================================================
# SG-1 Tests: MCP file operations under policy
# ===========================================================================


class TestFileWritePolicy:
    """SG-1.1 / SG-1.2: file_write with policy enforcement."""

    @pytest.mark.anyio()
    async def test_sg_1_1_secret_blocked_in_file_write(
        self, tmp_path: Path, audit_dir: Path
    ) -> None:
        """SG-1.1: file_write with secret content is denied by policy."""
        target = tmp_path / "config.py"

        async def check(session: ClientSession) -> None:
            result = await session.call_tool(
                "file_write",
                {
                    "path": str(target),
                    "content": (
                        "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
                    ),
                },
            )
            assert result.isError, "Expected denial but tool succeeded"
            error_text = result.content[0].text  # type: ignore[union-attr]
            assert "denied by policy" in error_text
            assert not target.exists(), "File should not be written when denied"

        await _with_server(check, load_builtins=True, audit_dir=audit_dir)

    @pytest.mark.anyio()
    async def test_sg_1_2_clean_write_allowed(
        self, tmp_path: Path, audit_dir: Path
    ) -> None:
        """SG-1.2: file_write with clean content is allowed."""
        target = tmp_path / "hello.txt"

        async def check(session: ClientSession) -> None:
            result = await session.call_tool(
                "file_write",
                {"path": str(target), "content": "Hello, world!\n"},
            )
            assert not result.isError, (
                f"Expected success: {result.content[0].text}"  # type: ignore[union-attr]
            )
            assert target.exists()
            assert target.read_text() == "Hello, world!\n"

        await _with_server(check, load_builtins=True, audit_dir=audit_dir)


class TestFileEditPolicy:
    """SG-1.3 / SG-1.4: file_edit with policy enforcement."""

    @pytest.mark.anyio()
    async def test_sg_1_3_secret_blocked_in_edit(
        self,
        tmp_path: Path,
        audit_dir: Path,
        file_edit_secret_policy_dir: Path,
    ) -> None:
        """SG-1.3: file_edit injecting secret content is denied."""
        target = tmp_path / "app.py"
        target.write_text("config = {}\n")

        async def check(session: ClientSession) -> None:
            result = await session.call_tool(
                "file_edit",
                {
                    "path": str(target),
                    "old_string": "config = {}",
                    "new_string": 'config = {"API_KEY = AKIAIOSFODNN7EXAMPLE"}',
                },
            )
            assert result.isError, "Expected denial but tool succeeded"
            error_text = result.content[0].text  # type: ignore[union-attr]
            assert "denied by policy" in error_text
            # Original content should be unchanged
            assert target.read_text() == "config = {}\n"

        await _with_server(
            check,
            policy_dir=file_edit_secret_policy_dir,
            audit_dir=audit_dir,
        )

    @pytest.mark.anyio()
    async def test_sg_1_4_normal_edit_allowed(
        self, tmp_path: Path, audit_dir: Path
    ) -> None:
        """SG-1.4: file_edit with clean content is allowed."""
        target = tmp_path / "readme.md"
        target.write_text("# Title\nOld content\n")

        async def check(session: ClientSession) -> None:
            result = await session.call_tool(
                "file_edit",
                {
                    "path": str(target),
                    "old_string": "Old content",
                    "new_string": "New content",
                },
            )
            assert not result.isError, (
                f"Expected success: {result.content[0].text}"  # type: ignore[union-attr]
            )
            assert "New content" in target.read_text()
            assert "Old content" not in target.read_text()

        await _with_server(check, load_builtins=True, audit_dir=audit_dir)


class TestFileReadAudit:
    """SG-1.5: file_read is audited."""

    @pytest.mark.anyio()
    async def test_sg_1_5_file_read_audited(
        self, tmp_path: Path, audit_dir: Path
    ) -> None:
        """SG-1.5: file_read records an audit entry."""
        target = tmp_path / "data.txt"
        target.write_text("Some data to read.\n")

        async def check(session: ClientSession) -> None:
            result = await session.call_tool("file_read", {"path": str(target)})
            assert not result.isError
            assert "Some data to read." in result.content[0].text  # type: ignore[union-attr]

            # Query audit log for the file_read action
            audit_result = await session.call_tool(
                "agentguard_audit_query",
                {"action": "file_read"},
            )
            assert not audit_result.isError
            entries = json.loads(
                audit_result.content[0].text  # type: ignore[union-attr]
            )
            assert len(entries) == 1
            read_entry = entries[-1]
            assert read_entry["action"] == "file_read"
            assert read_entry["result"] == "allowed"

        await _with_server(check, load_builtins=True, audit_dir=audit_dir)


class TestFileGlob:
    """SG-1.6: file_glob caps results at 100."""

    @pytest.mark.anyio()
    async def test_sg_1_6_file_glob_capped_at_100(
        self, tmp_path: Path, audit_dir: Path
    ) -> None:
        """SG-1.6: file_glob returns at most 100 results."""
        # Create 120 files
        sub = tmp_path / "many_files"
        sub.mkdir()
        for i in range(120):
            (sub / f"file_{i:04d}.txt").write_text(f"content {i}")

        async def check(session: ClientSession) -> None:
            result = await session.call_tool(
                "file_glob",
                {"pattern": "*.txt", "path": str(sub)},
            )
            assert not result.isError
            text = result.content[0].text  # type: ignore[union-attr]
            lines = [ln for ln in text.strip().splitlines() if ln.strip()]
            # Output includes file paths (max 100) plus optional info line
            file_lines = [ln for ln in lines if not ln.startswith("(")]
            assert len(file_lines) == 100
            # Verify capped message is present
            assert any("capped" in ln.lower() for ln in lines)

        await _with_server(check, load_builtins=True, audit_dir=audit_dir)


class TestFileGrep:
    """SG-1.7: file_grep finds matches."""

    @pytest.mark.anyio()
    async def test_sg_1_7_file_grep_matches(
        self, tmp_path: Path, audit_dir: Path
    ) -> None:
        """SG-1.7: file_grep returns matching lines."""
        target = tmp_path / "search_me.py"
        target.write_text(
            "def hello():\n"
            "    print('hello world')\n"
            "\n"
            "def goodbye():\n"
            "    print('goodbye world')\n"
        )

        async def check(session: ClientSession) -> None:
            result = await session.call_tool(
                "file_grep",
                {"pattern": "hello", "path": str(tmp_path)},
            )
            assert not result.isError
            text = result.content[0].text  # type: ignore[union-attr]
            assert "hello" in text

        await _with_server(check, load_builtins=True, audit_dir=audit_dir)


class TestFileList:
    """SG-1.8: file_list shows directory contents."""

    @pytest.mark.anyio()
    async def test_sg_1_8_file_list_directory(
        self, tmp_path: Path, audit_dir: Path
    ) -> None:
        """SG-1.8: file_list returns directory entries."""
        sub = tmp_path / "project"
        sub.mkdir()
        (sub / "main.py").write_text("print('hi')")
        (sub / "README.md").write_text("# README")
        inner = sub / "src"
        inner.mkdir()
        (inner / "lib.py").write_text("pass")

        async def check(session: ClientSession) -> None:
            result = await session.call_tool("file_list", {"path": str(sub)})
            assert not result.isError
            text = result.content[0].text  # type: ignore[union-attr]
            assert "main.py" in text
            assert "README.md" in text
            assert "src/" in text

        await _with_server(check, load_builtins=True, audit_dir=audit_dir)
