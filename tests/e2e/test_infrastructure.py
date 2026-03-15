"""Infrastructure smoke tests — verify E2E fixtures work.

These tests validate that the shared E2E fixtures are functional
and correctly configured. They serve as a foundation for the
actual E2E test suites.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

import httpx
import pytest

if TYPE_CHECKING:
    from pathlib import Path

    from tests.e2e.conftest import MockUpstream


class TestMockUpstream:
    """MockUpstream records requests and returns configured responses."""

    @pytest.mark.anyio()
    async def test_records_request(self, mock_upstream: MockUpstream) -> None:
        """Mock upstream records incoming requests."""
        transport = httpx.ASGITransport(app=mock_upstream.app)
        async with httpx.AsyncClient(
            transport=transport, base_url="http://mock"
        ) as client:
            await client.post(
                "/v1/chat/completions",
                json={"model": "gpt-4", "messages": []},
            )
        assert len(mock_upstream.requests) == 1
        assert mock_upstream.requests[0]["path"] == "/v1/chat/completions"
        assert mock_upstream.requests[0]["method"] == "POST"

    @pytest.mark.anyio()
    async def test_returns_configured_json(self, mock_upstream: MockUpstream) -> None:
        """Mock returns the configured JSON response."""
        mock_upstream.set_response(
            {"choices": [{"message": {"content": "hello"}}]}, status=200
        )
        transport = httpx.ASGITransport(app=mock_upstream.app)
        async with httpx.AsyncClient(
            transport=transport, base_url="http://mock"
        ) as client:
            resp = await client.get("/test")
        assert resp.status_code == 200
        assert resp.json()["choices"][0]["message"]["content"] == "hello"

    @pytest.mark.anyio()
    async def test_returns_sse_stream(self, mock_upstream: MockUpstream) -> None:
        """Mock returns SSE chunks when configured for streaming."""
        mock_upstream.set_sse_chunks(["chunk-1", "chunk-2"])
        transport = httpx.ASGITransport(app=mock_upstream.app)
        async with httpx.AsyncClient(
            transport=transport, base_url="http://mock"
        ) as client:
            resp = await client.get("/stream")
        assert resp.status_code == 200
        assert "text/event-stream" in resp.headers["content-type"]
        body = resp.text
        assert "data: chunk-1" in body
        assert "data: chunk-2" in body
        assert "data: [DONE]" in body


class TestProxyAppWithMock:
    """proxy_app_with_mock creates a working proxy ASGI app."""

    @pytest.mark.anyio()
    async def test_health_endpoint(self, proxy_app_with_mock: Any) -> None:
        """Proxy health endpoint returns 200 with session info."""
        transport = httpx.ASGITransport(app=proxy_app_with_mock)
        async with httpx.AsyncClient(
            transport=transport, base_url="http://proxy"
        ) as client:
            resp = await client.get("/_health")
        assert resp.status_code == 200
        data = resp.json()
        assert "session_id" in data
        assert data["upstream"] == "http://mock-upstream"

    @pytest.mark.anyio()
    async def test_forwards_to_mock(
        self,
        proxy_app_with_mock: Any,
        mock_upstream: MockUpstream,
    ) -> None:
        """Proxy forwards requests to the mock upstream."""
        mock_upstream.set_response({"choices": [{"message": {"content": "proxied"}}]})
        transport = httpx.ASGITransport(app=proxy_app_with_mock)
        async with httpx.AsyncClient(
            transport=transport, base_url="http://proxy"
        ) as client:
            resp = await client.post(
                "/v1/chat/completions",
                json={
                    "model": "gpt-4",
                    "messages": [{"role": "user", "content": "hi"}],
                },
            )
        assert resp.status_code == 200
        assert len(mock_upstream.requests) == 1


class TestTmpDirs:
    """Temporary directory fixtures create valid directories."""

    def test_tmp_audit_dir_exists(self, tmp_audit_dir: Path) -> None:
        """tmp_audit_dir creates an existing directory."""
        assert tmp_audit_dir.is_dir()
        assert tmp_audit_dir.name == "audit"

    def test_tmp_policy_dir_exists(self, tmp_policy_dir: Path) -> None:
        """tmp_policy_dir creates an existing directory."""
        assert tmp_policy_dir.is_dir()
        assert tmp_policy_dir.name == "policies"


class TestAuthJsonFile:
    """auth_json_file creates valid auth credentials."""

    def test_auth_file_content(self, auth_json_file: Path) -> None:
        """Auth file contains expected token structure."""
        data = json.loads(auth_json_file.read_text())
        assert "github-copilot" in data
        assert data["github-copilot"]["refresh"] == "test-token-12345"


class TestRsnPolicies:
    """rsn_policies copies built-in policy YAML files."""

    def test_policies_copied(self, rsn_policies: Path) -> None:
        """All built-in policy YAML files are copied."""
        yaml_files = list(rsn_policies.glob("*.yaml"))
        assert len(yaml_files) == 11
        names = {f.stem for f in yaml_files}
        assert "no-force-push" in names
        assert "no-secret-in-prompt" in names


class TestMcpServerWithPreset:
    """mcp_server_with_preset creates functional MCP servers."""

    def test_creates_server(self, mcp_server_with_preset: Any) -> None:
        """Factory creates a server with the given preset."""
        server = mcp_server_with_preset("balanced")
        assert server is not None
        assert server.name == "AgentGuard"

    def test_strict_preset(self, mcp_server_with_preset: Any) -> None:
        """Factory works with strict preset."""
        server = mcp_server_with_preset("strict")
        assert server is not None
