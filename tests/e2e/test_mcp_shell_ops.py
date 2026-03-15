"""E2E tests: MCP shell execution under policy (SG-2).

Tests the ``shell_execute`` MCP tool with policy enforcement using
the full MCP protocol via anyio memory streams.

Test matrix:
  SG-2.1  rm -rf denied by no-data-deletion
  SG-2.2  git push --force denied by no-force-push
  SG-2.3  git commit --no-verify denied by no-hook-bypass
  SG-2.4  git add .env denied by no-env-commit
  SG-2.5  Safe command (echo) allowed
  SG-2.6  stdout + stderr captured in result
  SG-2.7  Multiple policies first-match deny
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from tests.e2e.conftest import _get_text, _with_server

if TYPE_CHECKING:
    from pathlib import Path

    from mcp import ClientSession


# ===========================================================================
# SG-2 Tests: MCP shell execution under policy
# ===========================================================================


class TestShellDeletion:
    """SG-2.1: destructive removal commands are denied."""

    @pytest.mark.anyio()
    async def test_sg_2_1_rm_rf_denied(self, audit_dir: Path) -> None:
        """rm -rf /tmp/important-data is denied by no-data-deletion."""
        denied_cmd = "rm -rf /tmp/important-data"

        async def check(session: ClientSession) -> None:
            result = await session.call_tool(
                "shell_execute",
                {"command": denied_cmd},
            )
            assert result.isError, "Expected denial but tool succeeded"
            text = _get_text(result)
            assert "denied by policy" in text
            assert "no-data-deletion" in text

        await _with_server(check, audit_dir=audit_dir, preset="permissive")


class TestShellForcePush:
    """SG-2.2: force-push commands are denied."""

    @pytest.mark.anyio()
    async def test_sg_2_2_force_push_denied(self, audit_dir: Path) -> None:
        """git push --force is denied by no-force-push."""

        async def check(session: ClientSession) -> None:
            result = await session.call_tool(
                "shell_execute",
                {"command": "git push --force origin main"},
            )
            assert result.isError, "Expected denial but tool succeeded"
            text = _get_text(result)
            assert "denied by policy" in text
            assert "no-force-push" in text

        await _with_server(check, audit_dir=audit_dir, preset="permissive")


class TestShellNoVerify:
    """SG-2.3: --no-verify bypass is denied."""

    @pytest.mark.anyio()
    async def test_sg_2_3_no_verify_denied(self, audit_dir: Path) -> None:
        """git commit --no-verify is denied by no-hook-bypass."""

        async def check(session: ClientSession) -> None:
            result = await session.call_tool(
                "shell_execute",
                {"command": "git commit --no-verify -m 'bypass hooks'"},
            )
            assert result.isError, "Expected denial but tool succeeded"
            text = _get_text(result)
            assert "denied by policy" in text
            assert "no-hook-bypass" in text

        await _with_server(check, audit_dir=audit_dir, preset="balanced")


class TestShellEnvCommit:
    """SG-2.4: committing .env files is denied."""

    @pytest.mark.anyio()
    async def test_sg_2_4_env_commit_denied(self, audit_dir: Path) -> None:
        """git add .env is denied by no-env-commit."""

        async def check(session: ClientSession) -> None:
            result = await session.call_tool(
                "shell_execute",
                {"command": "git add .env"},
            )
            assert result.isError, "Expected denial but tool succeeded"
            text = _get_text(result)
            assert "denied by policy" in text
            assert "no-env-commit" in text

        await _with_server(check, audit_dir=audit_dir, preset="balanced")


class TestShellSafeCommand:
    """SG-2.5: safe commands pass through policy and execute."""

    @pytest.mark.anyio()
    async def test_sg_2_5_echo_allowed(self, audit_dir: Path) -> None:
        """A simple echo command is allowed and returns output."""

        async def check(session: ClientSession) -> None:
            result = await session.call_tool(
                "shell_execute",
                {"command": "echo hello-agentguard"},
            )
            assert not result.isError, f"Expected success: {_get_text(result)}"
            text = _get_text(result)
            assert "hello-agentguard" in text

        await _with_server(check, audit_dir=audit_dir, preset="strict")


class TestShellOutputCapture:
    """SG-2.6: stdout and stderr are both captured."""

    @pytest.mark.anyio()
    async def test_sg_2_6_stdout_stderr_captured(self, audit_dir: Path) -> None:
        """Both stdout and stderr appear in the tool result."""

        async def check(session: ClientSession) -> None:
            result = await session.call_tool(
                "shell_execute",
                {
                    "command": ("echo stdout-line && echo stderr-line >&2"),
                },
            )
            assert not result.isError, f"Expected success: {_get_text(result)}"
            text = _get_text(result)
            assert "stdout-line" in text
            assert "stderr-line" in text

        await _with_server(check, audit_dir=audit_dir, preset="permissive")


class TestShellMultiplePolicies:
    """SG-2.7: deny policy enforces command denial under strict preset."""

    @pytest.mark.anyio()
    async def test_sg_2_7_first_match_deny(self, audit_dir: Path) -> None:
        """A command matching multiple policies is denied by the first match.

        ``git push -f`` matches no-force-push. Under the strict preset
        all policies are loaded, so the denial happens on the first
        matching policy.
        """

        async def check(session: ClientSession) -> None:
            result = await session.call_tool(
                "shell_execute",
                {"command": "git push -f origin main"},
            )
            assert result.isError, "Expected denial but tool succeeded"
            text = _get_text(result)
            assert "denied by policy" in text
            # Under strict, no-force-push should match
            assert "no-force-push" in text

        await _with_server(check, audit_dir=audit_dir, preset="strict")
