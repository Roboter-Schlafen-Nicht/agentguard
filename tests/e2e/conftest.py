"""E2E test fixtures for AgentGuard.

Shared fixtures for end-to-end tests exercising full system
workflows including MCP server, proxy, mock upstream, policies,
and audit.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest
from starlette.applications import Starlette
from starlette.responses import JSONResponse, StreamingResponse
from starlette.routing import Route

from agentguard.proxy.app import create_app
from agentguard.proxy.config import ProxyConfig

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

    from starlette.requests import Request

# ---------------------------------------------------------------------------
# E2E marker auto-application
# ---------------------------------------------------------------------------

_BUILTIN_POLICY_DIR = (
    Path(__file__).resolve().parents[2]
    / "src"
    / "agentguard"
    / "policies"
    / "builtin_policies"
)


def pytest_collection_modifyitems(items: list[pytest.Item]) -> None:
    """Automatically mark all tests under tests/e2e/ with @pytest.mark.e2e."""
    e2e_dir = Path(__file__).parent
    for item in items:
        if Path(item.fspath).is_relative_to(e2e_dir):
            item.add_marker(pytest.mark.e2e)


# ---------------------------------------------------------------------------
# Mock upstream server
# ---------------------------------------------------------------------------


class MockUpstream:
    """A configurable mock LLM API upstream.

    Records all received requests and returns configurable responses.
    Supports both JSON (non-streaming) and SSE (streaming) modes.

    Usage::

        mock = MockUpstream()
        mock.set_response({"choices": [{"message": {"content": "Hello"}}]})
        # or for streaming:
        mock.set_sse_chunks(["chunk1", "chunk2"])
    """

    def __init__(self) -> None:
        self.requests: list[dict[str, Any]] = []
        self._response_body: dict[str, Any] = {
            "choices": [{"message": {"content": "test response"}}],
        }
        self._response_status: int = 200
        self._sse_chunks: list[str] | None = None
        self._sse_done_data: str = "[DONE]"
        self.app = Starlette(
            routes=[
                Route(
                    "/{path:path}",
                    self._handle,
                    methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
                ),
            ],
        )

    def set_response(
        self,
        body: dict[str, Any],
        *,
        status: int = 200,
    ) -> None:
        """Configure the JSON response body and status code."""
        self._response_body = body
        self._response_status = status
        self._sse_chunks = None

    def set_sse_chunks(
        self,
        chunks: list[str],
        *,
        done_data: str = "[DONE]",
    ) -> None:
        """Configure SSE streaming response chunks.

        Each chunk is sent as a ``data:`` line. A final
        ``data: [DONE]`` line is appended automatically.
        """
        self._sse_chunks = chunks
        self._sse_done_data = done_data

    async def _handle(self, request: Request) -> JSONResponse | StreamingResponse:
        """Record the request and return the configured response."""
        body = await request.body()
        self.requests.append(
            {
                "method": request.method,
                "path": request.url.path,
                "headers": dict(request.headers),
                "body": body.decode("utf-8", errors="replace") if body else "",
                "query": str(request.url.query),
            },
        )

        if self._sse_chunks is not None:
            return StreamingResponse(
                self._stream_sse(),
                media_type="text/event-stream",
                status_code=200,
            )
        return JSONResponse(self._response_body, status_code=self._response_status)

    async def _stream_sse(self) -> AsyncIterator[str]:
        """Yield SSE-formatted chunks."""
        for chunk in self._sse_chunks or []:
            yield f"data: {chunk}\n\n"
        yield f"data: {self._sse_done_data}\n\n"


@pytest.fixture()
def mock_upstream() -> MockUpstream:
    """Create a fresh MockUpstream instance.

    The mock records all requests and can be configured to return
    specific JSON or SSE responses.

    Returns:
        A :class:`MockUpstream` with its Starlette ``app`` attribute
        suitable for use with ``httpx.ASGITransport``.
    """
    return MockUpstream()


# ---------------------------------------------------------------------------
# Proxy app with mock upstream
# ---------------------------------------------------------------------------


@pytest.fixture()
def proxy_app_with_mock(
    mock_upstream: MockUpstream,
    tmp_path: Path,
) -> Starlette:
    """Create a proxy Starlette app connected to the mock upstream.

    The middleware's ``_forward_request`` and ``_forward_streaming``
    methods are monkey-patched to route through an ASGI transport
    pointing at the mock upstream.  All policy enforcement, audit
    logging, and response scanning still run normally.

    Returns:
        A Starlette ASGI app ready for ``httpx.AsyncClient`` testing.
    """
    import httpx

    from agentguard.proxy.middleware import _StreamContext

    audit_dir = tmp_path / "audit"
    audit_dir.mkdir()

    config = ProxyConfig(
        upstream_base_url="http://mock-upstream",
        audit_dir=str(audit_dir),
        load_builtins=True,
        scan_responses=True,
    )
    app = create_app(config)
    middleware = app.state.middleware
    transport = httpx.ASGITransport(app=mock_upstream.app)

    async def _patched_forward_request(
        method: str,
        url: str,
        headers: dict[str, str],
        body: bytes,
    ) -> Any:
        async with httpx.AsyncClient(
            transport=transport, base_url="http://mock-upstream"
        ) as client:
            return await client.request(
                method=method, url=url, headers=headers, content=body
            )

    async def _patched_forward_streaming(
        method: str,
        url: str,
        headers: dict[str, str],
        body: bytes,
    ) -> _StreamContext:
        client = httpx.AsyncClient(transport=transport, base_url="http://mock-upstream")
        try:
            response = await client.send(
                client.build_request(
                    method=method, url=url, headers=headers, content=body
                ),
                stream=True,
            )
        except Exception:
            await client.aclose()
            raise
        return _StreamContext(client=client, response=response)

    middleware._forward_request = _patched_forward_request
    middleware._forward_streaming = _patched_forward_streaming

    return app


# ---------------------------------------------------------------------------
# Temporary directories for audit and policies
# ---------------------------------------------------------------------------


@pytest.fixture()
def tmp_audit_dir(tmp_path: Path) -> Path:
    """Create and return a temporary audit directory.

    The directory is automatically cleaned up by pytest's ``tmp_path``.
    """
    d = tmp_path / "audit"
    d.mkdir()
    return d


@pytest.fixture()
def tmp_policy_dir(tmp_path: Path) -> Path:
    """Create and return a temporary policy directory.

    The directory is automatically cleaned up by pytest's ``tmp_path``.
    """
    d = tmp_path / "policies"
    d.mkdir()
    return d


# ---------------------------------------------------------------------------
# Auth JSON file
# ---------------------------------------------------------------------------


@pytest.fixture()
def auth_json_file(tmp_path: Path) -> Path:
    """Create an auth.json file with a test token.

    The file follows the OpenCode auth format::

        {"github-copilot": {"refresh": "test-token-12345"}}

    Returns:
        Path to the auth.json file.
    """
    auth_path = tmp_path / "auth.json"
    auth_data = {
        "github-copilot": {"refresh": "test-token-12345"},
    }
    auth_path.write_text(json.dumps(auth_data))
    return auth_path


# ---------------------------------------------------------------------------
# RSN built-in policies
# ---------------------------------------------------------------------------


@pytest.fixture()
def rsn_policies(tmp_path: Path) -> Path:
    """Copy all built-in policy YAML files to a temporary directory.

    Returns:
        Path to the temporary directory containing the policy files.
    """
    policy_dir = tmp_path / "rsn_policies"
    policy_dir.mkdir()

    if _BUILTIN_POLICY_DIR.is_dir():
        for yaml_file in _BUILTIN_POLICY_DIR.glob("*.yaml"):
            shutil.copy2(yaml_file, policy_dir / yaml_file.name)

    return policy_dir


# ---------------------------------------------------------------------------
# MCP server fixture
# ---------------------------------------------------------------------------


@pytest.fixture()
def mcp_server_with_preset(tmp_path: Path) -> Any:
    """Factory fixture that creates an MCP server with a given preset.

    Usage::

        def test_something(mcp_server_with_preset):
            server = mcp_server_with_preset("strict")
            # server is a FastMCP instance

    Returns:
        A callable that takes a preset name and returns a FastMCP server.
    """
    from agentguard.mcp.server import create_server

    def _factory(
        preset: str = "balanced",
        *,
        audit_dir: str | None = None,
        actor: str = "agent",
        policy_dir: str | None = None,
    ) -> Any:
        if audit_dir is None:
            ad = tmp_path / "mcp_audit"
            ad.mkdir(exist_ok=True)
            audit_dir = str(ad)
        return create_server(
            preset=preset,
            audit_dir=audit_dir,
            actor=actor,
            policy_dir=policy_dir,
        )

    return _factory
