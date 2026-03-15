"""E2E regression smoke tests.

Quick sanity checks for the 12 regression checklist items (R-1 through
R-12) from the AgentGuard E2E test plan.  Each test exercises one
critical path end-to-end.  They are intentionally lightweight — the
full scenario tests live in the dedicated SG-* test files.

These tests are designed to run fast and catch regressions in the
most important behavior.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

import httpx
import pytest

from agentguard.audit.log import AuditLog
from agentguard.policies.presets import PRESET_POLICIES, Preset
from tests.e2e.conftest import (
    _chat_body,
    _create_proxy,
    _fake_sk_key,
    _fake_sk_proj_key,
    _get_text,
    _with_server,
)

if TYPE_CHECKING:
    from pathlib import Path

    from mcp import ClientSession

    from tests.e2e.conftest import MockUpstream


# ===========================================================================
# R-1: MCP file_write with secret denied (SG-1.1)
# ===========================================================================


class TestR1FileWriteSecretDenied:
    """R-1: Writing a file containing an API key must be denied."""

    @pytest.mark.anyio()
    async def test_file_write_with_secret_denied(
        self, audit_dir: Path, tmp_path: Path
    ) -> None:
        target = tmp_path / "secret.txt"
        secret = _fake_sk_key()

        async def run(session: ClientSession) -> None:
            result = await session.call_tool(
                "file_write",
                {"path": str(target), "content": f"KEY={secret}"},
            )
            assert result.isError is True
            assert "denied" in _get_text(result).lower()

        await _with_server(run, audit_dir=audit_dir, preset="balanced")
        assert not target.exists()


# ===========================================================================
# R-2: MCP shell_execute with rm -rf denied (SG-2.1)
# ===========================================================================


class TestR2ShellDeleteDenied:
    """R-2: Destructive shell commands must be denied."""

    @pytest.mark.anyio()
    async def test_shell_rm_rf_denied(self, audit_dir: Path) -> None:
        async def run(session: ClientSession) -> None:
            result = await session.call_tool("shell_execute", {"command": "rm -rf /"})
            assert result.isError is True
            assert "denied" in _get_text(result).lower()

        await _with_server(run, audit_dir=audit_dir, preset="permissive")


# ===========================================================================
# R-3: Proxy blocks secret in prompt (SG-3.1)
# ===========================================================================


class TestR3ProxyBlocksSecret:
    """R-3: Proxy must block API keys in outbound prompts."""

    @pytest.mark.anyio()
    async def test_proxy_blocks_secret_in_prompt(
        self, mock_upstream: MockUpstream, audit_dir: Path
    ) -> None:
        proxy_app = _create_proxy(mock_upstream, audit_dir, preset="permissive")
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=proxy_app),
            base_url="http://proxy",
        ) as client:
            resp = await client.post(
                "/v1/chat/completions",
                json=_chat_body(f"Use key: {_fake_sk_proj_key()}"),
            )
        assert resp.status_code == 403
        assert len(mock_upstream.requests) == 0


# ===========================================================================
# R-4: Proxy SSE streaming forwards all chunks (SG-11.2)
# ===========================================================================


class TestR4SSEStreamingForwards:
    """R-4: SSE streaming must forward all chunks to the client."""

    @pytest.mark.anyio()
    async def test_sse_streaming_forwards_chunks(
        self, mock_upstream: MockUpstream, audit_dir: Path
    ) -> None:
        chunks = [
            json.dumps({"choices": [{"delta": {"content": "Hello"}}]}),
            json.dumps({"choices": [{"delta": {"content": " World"}}]}),
        ]
        mock_upstream.set_sse_chunks(chunks)

        proxy_app = _create_proxy(
            mock_upstream, audit_dir, preset="permissive", scan_responses=False
        )
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=proxy_app),
            base_url="http://proxy",
        ) as client:
            resp = await client.post(
                "/v1/chat/completions",
                json={
                    **_chat_body("Hi"),
                    "stream": True,
                },
            )
        assert resp.status_code == 200
        body = resp.text
        assert "Hello" in body
        assert "World" in body


# ===========================================================================
# R-5: Auth token injected from auth.json (SG-5.1)
# ===========================================================================


class TestR5AuthTokenInjected:
    """R-5: Auth token from auth.json must be injected into upstream requests."""

    @pytest.mark.anyio()
    async def test_auth_token_injected(
        self, mock_upstream: MockUpstream, tmp_path: Path
    ) -> None:
        mock_upstream.set_response({"choices": [{"message": {"content": "OK"}}]})

        audit_dir = tmp_path / "audit"
        audit_dir.mkdir()

        auth_path = tmp_path / "auth.json"
        auth_path.write_text(
            json.dumps({"github-copilot": {"refresh": "test-refresh-token"}})
        )

        proxy_app = _create_proxy(
            mock_upstream,
            audit_dir,
            auth_file=str(auth_path),
            auth_provider="github-copilot",
        )

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=proxy_app),
            base_url="http://proxy",
        ) as client:
            await client.post(
                "/v1/chat/completions",
                json=_chat_body("Hello"),
            )

        assert len(mock_upstream.requests) == 1
        auth_header = mock_upstream.requests[0]["headers"].get("authorization", "")
        assert "test-refresh-token" in auth_header


# ===========================================================================
# R-6: Audit hash chain verified clean (SG-7.1)
# ===========================================================================


class TestR6AuditHashChain:
    """R-6: Audit log hash chains must verify cleanly."""

    @pytest.mark.anyio()
    async def test_audit_hash_chain_valid(
        self, audit_dir: Path, tmp_path: Path
    ) -> None:
        target = tmp_path / "hash-test.txt"

        async def run(session: ClientSession) -> None:
            await session.call_tool(
                "file_write",
                {"path": str(target), "content": "hello\n"},
            )
            await session.call_tool("file_read", {"path": str(target)})

        await _with_server(run, audit_dir=audit_dir, preset="permissive")

        audit_logs = AuditLog.load_directory(audit_dir)
        assert len(audit_logs) >= 1
        for log in audit_logs:
            assert log.verify(), "Audit hash chain verification failed"


# ===========================================================================
# R-7: Preset loading correct policy counts (SG-6.1-6.3)
# ===========================================================================


class TestR7PresetPolicyCounts:
    """R-7: Preset bundles must load the expected number of policies."""

    def test_permissive_preset_count(self) -> None:
        policies = PRESET_POLICIES[Preset.PERMISSIVE]
        assert len(policies) == 3

    def test_balanced_preset_count(self) -> None:
        policies = PRESET_POLICIES[Preset.BALANCED]
        assert len(policies) == 8

    def test_strict_preset_count(self) -> None:
        policies = PRESET_POLICIES[Preset.STRICT]
        assert len(policies) == 11


# ===========================================================================
# R-8: CLI check command returns correct exit codes (SG-9.2-9.3)
# ===========================================================================


class TestR8CLICheckExitCodes:
    """R-8: CLI scan command returns correct exit codes."""

    def test_scan_clean_file_exits_zero(self, tmp_path: Path) -> None:
        """Scanning a clean file should exit 0."""
        import subprocess

        clean_file = tmp_path / "clean.py"
        clean_file.write_text("x = 1 + 2\n")

        result = subprocess.run(
            ["agentguard", "scan", str(clean_file)],
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert result.returncode == 0

    def test_scan_file_with_secret_exits_nonzero(self, tmp_path: Path) -> None:
        """Scanning a file with a secret pattern should exit non-zero."""
        import subprocess

        secret = _fake_sk_key()
        risky_file = tmp_path / "risky.py"
        risky_file.write_text(f'API_KEY = "{secret}"\n')

        result = subprocess.run(
            ["agentguard", "scan", str(risky_file)],
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert result.returncode != 0


# ===========================================================================
# R-9: Trust verify detects tampering (SG-8.3)
# ===========================================================================


class TestR9TrustDetectsTampering:
    """R-9: Trust scanner detects tampered audit files."""

    @pytest.mark.anyio()
    async def test_tampered_audit_detected(
        self, audit_dir: Path, tmp_path: Path
    ) -> None:
        target = tmp_path / "trust-test.txt"

        async def run(session: ClientSession) -> None:
            await session.call_tool(
                "file_write",
                {"path": str(target), "content": "data\n"},
            )
            await session.call_tool("file_read", {"path": str(target)})

        await _with_server(run, audit_dir=audit_dir, preset="permissive")

        # Tamper with the audit file
        audit_files = list(audit_dir.glob("ag-*.jsonl"))
        assert len(audit_files) >= 1

        content = audit_files[0].read_text()
        lines = content.strip().split("\n")
        assert len(lines) >= 2

        # Modify the second entry's action field
        entry = json.loads(lines[1])
        entry["action"] = "TAMPERED"
        lines[1] = json.dumps(entry)
        audit_files[0].write_text("\n".join(lines) + "\n")

        # Verify detects tampering
        logs = AuditLog.load_directory(audit_dir)
        assert len(logs) >= 1
        # At least one log must fail verification after tampering
        assert any(not log.verify() for log in logs)


# ===========================================================================
# R-10: RSN project policies auto-discovered (SG-12.7)
# ===========================================================================


class TestR10RSNPoliciesDiscovered:
    """R-10: RSN built-in policies are auto-discovered and loaded."""

    @pytest.mark.anyio()
    async def test_rsn_policies_loaded(self, audit_dir: Path) -> None:
        """MCP server with balanced preset should have RSN policies active."""

        async def run(session: ClientSession) -> None:
            # List tools to verify server started with policies
            tools = await session.list_tools()
            tool_names = [t.name for t in tools.tools]
            assert "file_write" in tool_names
            assert "shell_execute" in tool_names

            # Verify policy enforcement works — rm -rf should be denied
            result = await session.call_tool(
                "shell_execute", {"command": "rm -rf /tmp/test"}
            )
            assert result.isError is True

        await _with_server(run, audit_dir=audit_dir, preset="balanced")


# ===========================================================================
# R-11: Proxy handles upstream connection failure (SG-5.8)
# ===========================================================================


class TestR11UpstreamConnectionFailure:
    """R-11: Proxy must handle upstream connection failure gracefully."""

    @pytest.mark.anyio()
    async def test_upstream_failure_returns_error(
        self, mock_upstream: MockUpstream, tmp_path: Path
    ) -> None:
        audit_dir = tmp_path / "audit"
        audit_dir.mkdir()

        proxy_app = _create_proxy(mock_upstream, audit_dir)
        middleware = proxy_app.state.middleware

        # Override forwarding to simulate upstream connection failure
        async def _failing_forward(
            method: str,
            url: str,
            headers: dict[str, str],
            body: bytes,
        ) -> Any:
            raise httpx.ConnectError("Connection refused")

        middleware._forward_request = _failing_forward
        middleware._forward_streaming = _failing_forward

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=proxy_app),
            base_url="http://proxy",
        ) as client:
            resp = await client.post(
                "/v1/chat/completions",
                json=_chat_body("Hello"),
            )

        # Should return 502, not crash
        assert resp.status_code == 502


# ===========================================================================
# R-12: Dual-layer enforcement independent (SG-14.1)
# ===========================================================================


class TestR12DualLayerIndependent:
    """R-12: MCP and proxy layers enforce independently."""

    @pytest.mark.anyio()
    async def test_mcp_denial_does_not_affect_proxy(
        self, mock_upstream: MockUpstream, audit_dir: Path
    ) -> None:
        mock_upstream.set_response({"choices": [{"message": {"content": "OK"}}]})

        # MCP: denied (rm -rf)
        async def run_mcp(session: ClientSession) -> None:
            result = await session.call_tool("shell_execute", {"command": "rm -rf /"})
            assert result.isError is True

        await _with_server(run_mcp, audit_dir=audit_dir, preset="permissive")

        # Proxy: allowed (clean prompt)
        proxy_app = _create_proxy(mock_upstream, audit_dir, preset="permissive")
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=proxy_app),
            base_url="http://proxy",
        ) as client:
            resp = await client.post(
                "/v1/chat/completions",
                json=_chat_body("What is 2+2?"),
            )

        assert resp.status_code == 200
        assert len(mock_upstream.requests) == 1
