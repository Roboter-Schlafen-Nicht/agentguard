"""E2E tests: Dual-layer enforcement (SG-14).

Tests running both enforcement layers simultaneously, as configured in
the RSN two-layer setup.  The MCP layer blocks dangerous tool calls;
the proxy layer blocks dangerous content in LLM API traffic.

The layers are independent: one layer's denial does not affect the
other.  Both write audit entries to the same directory in separate
JSONL files (``ag-*.jsonl`` for MCP, ``proxy-*.jsonl`` for proxy).

Test matrix:
    SG-14.1  MCP blocks shell while proxy allows clean prompts
    SG-14.2  Proxy blocks secret while MCP allows clean file ops
    SG-14.3  Both layers deny simultaneously
    SG-14.4  Combined audit provides complete action timeline
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import httpx
import pytest

from agentguard.audit.log import AuditLog
from tests.e2e.conftest import (
    _audit_entries,
    _chat_body,
    _create_proxy,
    _fake_ghp_token,
    _fake_sk_key,
    _fake_sk_proj_key,
    _get_text,
    _mcp_audit_entries,
    _proxy_audit_entries,
    _with_server,
)

if TYPE_CHECKING:
    from pathlib import Path

    from mcp import ClientSession

    from tests.e2e.conftest import MockUpstream


# ===========================================================================
# SG-14 Tests: Dual-Layer Enforcement
# ===========================================================================


class TestMCPBlocksShellWhileProxyAllowsClean:
    """SG-14.1: MCP blocks dangerous shell command while proxy allows
    clean prompts.

    Both layers run with the ``permissive`` preset.  Proxy receives a
    clean prompt (allowed).  MCP receives ``rm -rf /`` (denied by
    ``no-data-deletion``).  Each layer produces independent audit
    entries.
    """

    @pytest.mark.anyio()
    async def test_sg_14_1_proxy_allows_clean_prompt(
        self, mock_upstream: MockUpstream, audit_dir: Path
    ) -> None:
        """Clean prompt passes proxy while dangerous shell is blocked by MCP."""
        mock_upstream.set_response({"choices": [{"message": {"content": "Hello!"}}]})

        # --- Proxy layer: clean prompt should be allowed ---
        proxy_app = _create_proxy(mock_upstream, audit_dir, preset="permissive")
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=proxy_app),
            base_url="http://proxy",
        ) as client:
            proxy_resp = await client.post(
                "/v1/chat/completions",
                json=_chat_body("What is the capital of France?"),
            )

        assert proxy_resp.status_code == 200
        assert len(mock_upstream.requests) == 1

        # --- MCP layer: dangerous shell should be blocked ---
        mcp_results: dict[str, Any] = {}

        async def run_mcp(session: ClientSession) -> None:
            result = await session.call_tool("shell_execute", {"command": "rm -rf /"})
            mcp_results["denied"] = result.isError
            mcp_results["text"] = _get_text(result)

        await _with_server(run_mcp, audit_dir=audit_dir, preset="permissive")

        assert mcp_results["denied"] is True
        assert "denied" in mcp_results["text"].lower()

    @pytest.mark.anyio()
    async def test_sg_14_1_independent_audit_entries(
        self, mock_upstream: MockUpstream, audit_dir: Path
    ) -> None:
        """Each layer produces its own audit entries independently."""
        mock_upstream.set_response({"choices": [{"message": {"content": "OK"}}]})

        # Proxy: clean prompt
        proxy_app = _create_proxy(mock_upstream, audit_dir, preset="permissive")
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=proxy_app),
            base_url="http://proxy",
        ) as client:
            await client.post(
                "/v1/chat/completions",
                json=_chat_body("Explain quantum computing."),
            )

        # MCP: dangerous shell
        async def run_mcp(session: ClientSession) -> None:
            await session.call_tool("shell_execute", {"command": "rm -rf /home"})

        await _with_server(run_mcp, audit_dir=audit_dir, preset="permissive")

        # Verify separate JSONL files
        mcp_files = list(audit_dir.glob("ag-*.jsonl"))
        proxy_files = list(audit_dir.glob("proxy-*.jsonl"))
        assert len(mcp_files) == 1, "Expected exactly one MCP audit file"
        assert len(proxy_files) == 1, "Expected exactly one proxy audit file"

        # Verify audit content
        mcp_entries = _mcp_audit_entries(audit_dir)
        proxy_entries = _proxy_audit_entries(audit_dir)

        assert any(
            e["result"] == "denied" and e["action"] == "shell_execute"
            for e in mcp_entries
        ), "MCP should have a denied shell_execute entry"

        assert any(
            e["result"] == "allowed" and e["action"] == "llm_request"
            for e in proxy_entries
        ), "Proxy should have an allowed llm_request entry"

    @pytest.mark.anyio()
    async def test_sg_14_1_both_hash_chains_valid(
        self, mock_upstream: MockUpstream, audit_dir: Path
    ) -> None:
        """Both MCP and proxy audit hash chains are independently valid."""
        mock_upstream.set_response({"choices": [{"message": {"content": "Hi"}}]})

        # Proxy: allowed
        proxy_app = _create_proxy(mock_upstream, audit_dir, preset="permissive")
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=proxy_app),
            base_url="http://proxy",
        ) as client:
            await client.post(
                "/v1/chat/completions",
                json=_chat_body("Hello"),
            )

        # MCP: denied
        async def run_mcp(session: ClientSession) -> None:
            await session.call_tool("shell_execute", {"command": "rm -rf /tmp/danger"})

        await _with_server(run_mcp, audit_dir=audit_dir, preset="permissive")

        # Load and verify each chain independently
        audit_logs = AuditLog.load_directory(audit_dir)
        assert len(audit_logs) == 2, "Expected at least 2 audit log files"

        for log in audit_logs:
            assert log.verify(), (
                f"Hash chain verification failed for audit log "
                f"with {len(log.entries)} entries"
            )


class TestProxyBlocksSecretWhileMCPAllowsFileOps:
    """SG-14.2: Proxy blocks secret in prompt while MCP allows clean
    file ops.

    Proxy layer denies a prompt containing an API key (blocked by
    ``no-secret-in-prompt``).  MCP layer allows a clean file_write
    (no policy violation).  Independent enforcement — one layer's
    denial does not affect the other.
    """

    @pytest.mark.anyio()
    async def test_sg_14_2_proxy_blocks_secret(
        self, mock_upstream: MockUpstream, audit_dir: Path, tmp_path: Path
    ) -> None:
        """Proxy blocks API key in prompt; MCP allows clean file write."""
        # --- Proxy layer: secret in prompt should be blocked ---
        proxy_app = _create_proxy(mock_upstream, audit_dir, preset="permissive")
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=proxy_app),
            base_url="http://proxy",
        ) as client:
            proxy_resp = await client.post(
                "/v1/chat/completions",
                json=_chat_body(f"Use this key: {_fake_sk_proj_key()}"),
            )

        assert proxy_resp.status_code == 403
        body = proxy_resp.json()
        assert "denied" in body.get("error", "")
        assert body.get("denied_by") == "no-secret-in-prompt"
        # Request must NOT reach upstream
        assert len(mock_upstream.requests) == 0

        # --- MCP layer: clean file_write should be allowed ---
        target_file = tmp_path / "clean-output.txt"
        mcp_results: dict[str, Any] = {}

        async def run_mcp(session: ClientSession) -> None:
            result = await session.call_tool(
                "file_write",
                {"path": str(target_file), "content": "Hello, world!\n"},
            )
            mcp_results["error"] = result.isError
            mcp_results["text"] = _get_text(result)

        await _with_server(run_mcp, audit_dir=audit_dir, preset="permissive")

        assert mcp_results["error"] is False
        assert target_file.read_text() == "Hello, world!\n"

    @pytest.mark.anyio()
    async def test_sg_14_2_independent_enforcement(
        self, mock_upstream: MockUpstream, audit_dir: Path, tmp_path: Path
    ) -> None:
        """One layer's denial does not affect the other."""
        # Proxy: denied (secret in prompt)
        proxy_app = _create_proxy(mock_upstream, audit_dir, preset="permissive")
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=proxy_app),
            base_url="http://proxy",
        ) as client:
            await client.post(
                "/v1/chat/completions",
                json=_chat_body(
                    f"Key: {_fake_sk_proj_key('XXXXXXXXXXXXXXXXXXXXXXXXXXXXXX12')}"
                ),
            )

        # MCP: allowed (clean file write AFTER proxy denial)
        target_file = tmp_path / "after-denial.txt"

        async def run_mcp(session: ClientSession) -> None:
            result = await session.call_tool(
                "file_write",
                {"path": str(target_file), "content": "Still works!\n"},
            )
            assert result.isError is False

        await _with_server(run_mcp, audit_dir=audit_dir, preset="permissive")

        # MCP must still work even though proxy just denied
        assert target_file.exists()
        assert target_file.read_text() == "Still works!\n"

        # Verify audit shows independent results
        proxy_entries = _proxy_audit_entries(audit_dir)
        mcp_entries = _mcp_audit_entries(audit_dir)

        assert any(e["result"] == "denied" for e in proxy_entries)
        assert any(e["result"] == "allowed" for e in mcp_entries)


class TestBothLayersDenySimultaneously:
    """SG-14.3: Both layers deny simultaneously on related actions.

    MCP layer denies file_write containing a secret (``no-secret-exposure``
    from ``balanced`` preset).  Proxy layer denies a prompt with the
    same secret (``no-secret-in-prompt``).  Both audit logs record
    denials with correct policy names.
    """

    @pytest.mark.anyio()
    async def test_sg_14_3_both_layers_deny(
        self, mock_upstream: MockUpstream, audit_dir: Path, tmp_path: Path
    ) -> None:
        """Both MCP and proxy deny independently for same secret pattern."""
        # Secret must match BOTH policy regexes:
        # - no-secret-exposure (MCP):   sk-[a-zA-Z0-9]{20,}
        # - no-secret-in-prompt (proxy): sk-(?:proj-)?[A-Za-z0-9]{20,}
        secret = _fake_sk_key("ABCDEFGHIJKLMNOPQRSTUVWXYZ12345678901234")

        # --- MCP layer: file_write with secret denied ---
        target_file = tmp_path / "leaked-secret.txt"

        async def run_mcp(session: ClientSession) -> None:
            result = await session.call_tool(
                "file_write",
                {"path": str(target_file), "content": f"API_KEY = {secret}"},
            )
            assert result.isError is True
            assert "denied" in _get_text(result).lower()

        await _with_server(run_mcp, audit_dir=audit_dir, preset="balanced")

        # File must NOT be written
        assert not target_file.exists()

        # --- Proxy layer: prompt with same secret denied ---
        proxy_app = _create_proxy(mock_upstream, audit_dir, preset="balanced")
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=proxy_app),
            base_url="http://proxy",
        ) as client:
            proxy_resp = await client.post(
                "/v1/chat/completions",
                json=_chat_body(f"Use this API key: {secret}"),
            )

        assert proxy_resp.status_code == 403
        assert len(mock_upstream.requests) == 0

    @pytest.mark.anyio()
    async def test_sg_14_3_correct_policy_names_in_audit(
        self, mock_upstream: MockUpstream, audit_dir: Path, tmp_path: Path
    ) -> None:
        """Both audit logs record denials with correct policy names."""
        # Same secret pattern that matches both policy regexes
        secret = _fake_sk_key("YYYYYYYYYYYYYYYYYYYYZZZZZZZZZZZZZZZZZ567890")

        # MCP: denied by no-secret-exposure
        target_file = tmp_path / "secret-check.txt"

        async def run_mcp(session: ClientSession) -> None:
            await session.call_tool(
                "file_write",
                {"path": str(target_file), "content": f"KEY = {secret}"},
            )

        await _with_server(run_mcp, audit_dir=audit_dir, preset="balanced")

        # Proxy: denied by no-secret-in-prompt
        proxy_app = _create_proxy(mock_upstream, audit_dir, preset="balanced")
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=proxy_app),
            base_url="http://proxy",
        ) as client:
            await client.post(
                "/v1/chat/completions",
                json=_chat_body(f"Here is my key: {secret}"),
            )

        # Check MCP audit — denied file_write
        # Note: MCP server records result="denied" but does not include
        # denied_by in metadata (only the proxy middleware does).
        mcp_entries = _mcp_audit_entries(audit_dir)
        mcp_denied = [e for e in mcp_entries if e["result"] == "denied"]
        assert len(mcp_denied) == 1
        assert any(e["action"] == "file_write" for e in mcp_denied), (
            f"Expected denied file_write in MCP entries: {mcp_denied}"
        )

        # Check proxy audit — denied by no-secret-in-prompt
        # Proxy middleware includes denied_by in metadata.
        proxy_entries = _proxy_audit_entries(audit_dir)
        proxy_denied = [e for e in proxy_entries if e["result"] == "denied"]
        assert len(proxy_denied) == 1
        assert any(
            e.get("metadata", {}).get("denied_by") == "no-secret-in-prompt"
            for e in proxy_denied
        ), f"Expected no-secret-in-prompt in proxy denied entries: {proxy_denied}"


class TestCombinedAuditTimeline:
    """SG-14.4: Combined audit provides complete action timeline.

    Mixed operations across both layers produce audit entries in the
    same directory.  Together they provide a complete timeline of all
    agent actions.
    """

    @pytest.mark.anyio()
    async def test_sg_14_4_shared_audit_directory(
        self, mock_upstream: MockUpstream, audit_dir: Path, tmp_path: Path
    ) -> None:
        """MCP and proxy audit files coexist in the same directory."""
        mock_upstream.set_response({"choices": [{"message": {"content": "Done"}}]})

        # MCP: multiple file operations
        file_a = tmp_path / "file-a.txt"
        file_b = tmp_path / "file-b.txt"

        async def run_mcp(session: ClientSession) -> None:
            await session.call_tool(
                "file_write",
                {"path": str(file_a), "content": "alpha\n"},
            )
            await session.call_tool(
                "file_write",
                {"path": str(file_b), "content": "beta\n"},
            )
            await session.call_tool("file_read", {"path": str(file_a)})

        await _with_server(run_mcp, audit_dir=audit_dir, preset="permissive")

        # Proxy: two requests (one allowed, one denied)
        proxy_app = _create_proxy(mock_upstream, audit_dir, preset="permissive")
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=proxy_app),
            base_url="http://proxy",
        ) as client:
            # Clean prompt — allowed
            await client.post(
                "/v1/chat/completions",
                json=_chat_body("Summarize this document."),
            )
            # Secret in prompt — denied
            await client.post(
                "/v1/chat/completions",
                json=_chat_body(f"Key: {_fake_sk_proj_key()}"),
            )

        # Both file types must exist
        mcp_files = list(audit_dir.glob("ag-*.jsonl"))
        proxy_files = list(audit_dir.glob("proxy-*.jsonl"))
        assert len(mcp_files) == 1
        assert len(proxy_files) == 1

    @pytest.mark.anyio()
    async def test_sg_14_4_complete_timeline(
        self, mock_upstream: MockUpstream, audit_dir: Path, tmp_path: Path
    ) -> None:
        """All actions from both layers appear in the combined timeline."""
        mock_upstream.set_response({"choices": [{"message": {"content": "OK"}}]})

        # MCP: write + read + denied shell
        target = tmp_path / "timeline.txt"

        async def run_mcp(session: ClientSession) -> None:
            await session.call_tool(
                "file_write",
                {"path": str(target), "content": "timeline test\n"},
            )
            await session.call_tool("file_read", {"path": str(target)})
            await session.call_tool("shell_execute", {"command": "rm -rf /danger"})

        await _with_server(run_mcp, audit_dir=audit_dir, preset="permissive")

        # Proxy: allowed + denied
        proxy_app = _create_proxy(mock_upstream, audit_dir, preset="permissive")
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=proxy_app),
            base_url="http://proxy",
        ) as client:
            await client.post(
                "/v1/chat/completions",
                json=_chat_body("Explain gravity."),
            )
            await client.post(
                "/v1/chat/completions",
                json=_chat_body(_fake_ghp_token()),
            )

        # Collect ALL entries from both layers
        all_entries = _audit_entries(audit_dir)

        # Expected actions in timeline
        actions = [e["action"] for e in all_entries]
        results = [e["result"] for e in all_entries]

        # MCP actions present
        assert "file_write" in actions
        assert "file_read" in actions
        assert "shell_execute" in actions

        # Proxy actions present
        assert "llm_request" in actions

        # Both allowed and denied present
        assert "allowed" in results
        assert "denied" in results
        # 2 denied: shell_execute (MCP) + ghp-token llm_request (proxy)
        assert results.count("denied") == 2, (
            f"Expected 2 denials, got {results.count('denied')}"
        )
        # 3 allowed: file_write + file_read (MCP) + clean llm_request
        assert results.count("allowed") == 3, (
            f"Expected 3 allowed, got {results.count('allowed')}"
        )

        # Verify the specific proxy denial entry for the secret
        proxy_denials = [
            e
            for e in all_entries
            if e["action"] == "llm_request" and e["result"] == "denied"
        ]
        assert len(proxy_denials) == 1, (
            f"Expected 1 proxy denial, got {len(proxy_denials)}"
        )
        assert proxy_denials[0]["metadata"]["denied_by"] == ("no-secret-in-prompt")

        # At least 5 entries: 3 MCP + 2 proxy
        assert len(all_entries) == 5, (
            f"Expected 5 audit entries, got {len(all_entries)}: {actions}"
        )

    @pytest.mark.anyio()
    async def test_sg_14_4_all_hash_chains_valid(
        self, mock_upstream: MockUpstream, audit_dir: Path, tmp_path: Path
    ) -> None:
        """Each audit log file has a valid hash chain."""
        mock_upstream.set_response({"choices": [{"message": {"content": "OK"}}]})

        # MCP: allowed
        target = tmp_path / "chain-test.txt"

        async def run_mcp(session: ClientSession) -> None:
            await session.call_tool(
                "file_write",
                {"path": str(target), "content": "chain\n"},
            )

        await _with_server(run_mcp, audit_dir=audit_dir, preset="permissive")

        # Proxy: allowed
        proxy_app = _create_proxy(mock_upstream, audit_dir, preset="permissive")
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=proxy_app),
            base_url="http://proxy",
        ) as client:
            await client.post(
                "/v1/chat/completions",
                json=_chat_body("Test chain integrity."),
            )

        # Every audit log file must have a valid chain
        audit_logs = AuditLog.load_directory(audit_dir)
        assert len(audit_logs) == 2

        for log in audit_logs:
            assert log.verify(), (
                f"Hash chain failed for log with {len(log.entries)} entries"
            )

    @pytest.mark.anyio()
    async def test_sg_14_4_entries_have_timestamps(
        self, mock_upstream: MockUpstream, audit_dir: Path, tmp_path: Path
    ) -> None:
        """All audit entries have timestamps for timeline ordering."""
        mock_upstream.set_response({"choices": [{"message": {"content": "OK"}}]})

        # MCP
        target = tmp_path / "ts-test.txt"

        async def run_mcp(session: ClientSession) -> None:
            await session.call_tool(
                "file_write",
                {"path": str(target), "content": "ts\n"},
            )

        await _with_server(run_mcp, audit_dir=audit_dir, preset="permissive")

        # Proxy
        proxy_app = _create_proxy(mock_upstream, audit_dir, preset="permissive")
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=proxy_app),
            base_url="http://proxy",
        ) as client:
            await client.post(
                "/v1/chat/completions",
                json=_chat_body("Timestamp test."),
            )

        all_entries = _audit_entries(audit_dir)
        assert len(all_entries) == 2

        for entry in all_entries:
            assert "timestamp" in entry, f"Entry missing timestamp: {entry}"
            # Timestamps must be ISO format strings
            assert isinstance(entry["timestamp"], str)
            assert "T" in entry["timestamp"]  # ISO 8601
