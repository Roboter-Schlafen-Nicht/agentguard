"""E2E test fixtures for AgentGuard.

Shared fixtures and helpers for end-to-end tests exercising full system
workflows including MCP server, proxy, mock upstream, policies,
and audit.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import TYPE_CHECKING, Any

import anyio
import httpx
import pytest
from mcp import ClientSession
from starlette.applications import Starlette
from starlette.responses import JSONResponse, StreamingResponse
from starlette.routing import Route

from agentguard.proxy.app import create_app
from agentguard.proxy.config import ProxyConfig
from agentguard.proxy.middleware import _StreamContext

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
# Common anyio backend fixture
# ---------------------------------------------------------------------------


@pytest.fixture()
def anyio_backend() -> str:
    """Use asyncio as the anyio backend."""
    return "asyncio"


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
    audit_dir = tmp_path / "audit"
    audit_dir.mkdir()

    config = ProxyConfig(
        upstream_base_url="http://mock-upstream",
        audit_dir=str(audit_dir),
        load_builtins=True,
        scan_responses=True,
    )
    app = create_app(config)
    _patch_proxy_forwarding(app, mock_upstream)

    return app


# ---------------------------------------------------------------------------
# Temporary directories for audit and policies
# ---------------------------------------------------------------------------


@pytest.fixture()
def audit_dir(tmp_path: Path) -> Path:
    """Create and return a temporary audit directory.

    The directory is automatically cleaned up by pytest's ``tmp_path``.
    """
    d = tmp_path / "audit"
    d.mkdir()
    return d


# Keep the old name as an alias for backward compatibility.
tmp_audit_dir = audit_dir


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


# ---------------------------------------------------------------------------
# Shared MCP helpers
# ---------------------------------------------------------------------------


def get_text(result: Any) -> str:
    """Extract text from an MCP ``CallToolResult``."""
    return result.content[0].text  # type: ignore[no-any-return]


# Underscore aliases used by test modules via ``from tests.e2e.conftest import …``.
_get_text = get_text


async def with_server(
    fn: Any,
    *,
    audit_dir: Path | None = None,
    preset: str | None = None,
    actor: str = "test-agent",
    policy_dir: str | Path | None = None,
    load_builtins: bool = False,
    auto_discover: bool = False,
    trust_registry: str | None = None,
) -> None:
    """Spin up an AgentGuard MCP server in-process and run *fn(session)*.

    Uses anyio memory streams so no real I/O is needed.
    The server is cancelled once *fn* returns.

    This is the unified helper — accepts the union of parameters
    used across all E2E test modules.
    """
    from agentguard.mcp.server import create_server

    kwargs: dict[str, Any] = {
        "audit_dir": str(audit_dir) if audit_dir else None,
        "actor": actor,
        "load_builtins": load_builtins,
        "auto_discover": auto_discover,
    }
    if preset is not None:
        kwargs["preset"] = preset
    if policy_dir is not None:
        kwargs["policy_dir"] = str(policy_dir)
    if trust_registry is not None:
        kwargs["trust_registry"] = trust_registry

    app = create_server(**kwargs)
    server = app._mcp_server

    s2c_send, s2c_recv = anyio.create_memory_object_stream[Any](50)
    c2s_send, c2s_recv = anyio.create_memory_object_stream[Any](50)

    async with anyio.create_task_group() as tg:

        async def run_server() -> None:
            await server.run(
                c2s_recv,
                s2c_send,
                server.create_initialization_options(),
            )

        async def run_client() -> None:
            async with ClientSession(s2c_recv, c2s_send) as session:
                await session.initialize()
                await fn(session)
                tg.cancel_scope.cancel()

        tg.start_soon(run_server)
        tg.start_soon(run_client)


# Underscore alias for backward compatibility.
_with_server = with_server


# ---------------------------------------------------------------------------
# Shared proxy helpers
# ---------------------------------------------------------------------------


def _patch_proxy_forwarding(app: Starlette, mock_upstream: MockUpstream) -> None:
    """Monkey-patch proxy middleware to route through mock upstream.

    This is the single implementation of the forwarding monkey-patch
    used by ``proxy_app_with_mock``, ``create_proxy``, and
    ``create_proxy_with_auth``.
    """
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


def create_proxy(
    mock_upstream: MockUpstream,
    audit_dir: Path,
    *,
    preset: str | None = None,
    load_builtins: bool = False,
    scan_responses: bool = False,
    auth_file: str | None = None,
    auth_provider: str = "github-copilot",
) -> Starlette:
    """Build a proxy app wired to the mock upstream.

    Unified helper accepting the union of parameters used across
    all E2E test modules for proxy construction.

    Returns the Starlette app with monkey-patched forwarding.
    """
    config = ProxyConfig(
        upstream_base_url="http://mock-upstream",
        audit_dir=str(audit_dir),
        preset=preset,
        load_builtins=load_builtins,
        scan_responses=scan_responses,
        auth_file=auth_file if auth_file else None,
        auth_provider=auth_provider,
    )
    app = create_app(config)
    _patch_proxy_forwarding(app, mock_upstream)

    return app


# Underscore alias for backward compatibility.
_create_proxy = create_proxy


# ---------------------------------------------------------------------------
# Shared request/response body builders
# ---------------------------------------------------------------------------


def chat_body(content: str = "Hello", *, stream: bool = False) -> dict[str, Any]:
    """Build a minimal OpenAI chat completion request body."""
    body: dict[str, Any] = {
        "model": "gpt-4",
        "messages": [{"role": "user", "content": content}],
    }
    if stream:
        body["stream"] = True
    return body


# Underscore alias for backward compatibility.
_chat_body = chat_body


def streaming_body(content: str = "Hello") -> dict[str, Any]:
    """Build a minimal OpenAI streaming chat request body."""
    return {
        "model": "gpt-4",
        "stream": True,
        "messages": [{"role": "user", "content": content}],
    }


def sse_chunk(content: str, index: int = 0) -> str:
    """Build an OpenAI-format SSE chunk payload (raw JSON string)."""
    return json.dumps(
        {
            "id": f"chatcmpl-{index}",
            "object": "chat.completion.chunk",
            "choices": [
                {
                    "index": 0,
                    "delta": {"content": content},
                    "finish_reason": None,
                }
            ],
        }
    )


def sse_done_chunk() -> str:
    """Build an OpenAI-format SSE final chunk (finish_reason=stop)."""
    return json.dumps(
        {
            "id": "chatcmpl-final",
            "object": "chat.completion.chunk",
            "choices": [
                {
                    "index": 0,
                    "delta": {},
                    "finish_reason": "stop",
                }
            ],
        }
    )


def parse_sse_events(raw: str) -> list[str]:
    """Extract ``data:`` payloads from raw SSE text."""
    events: list[str] = []
    for line in raw.split("\n"):
        stripped = line.strip()
        if stripped.startswith("data: "):
            events.append(stripped[6:])
    return events


# Underscore aliases for backward compatibility.
_streaming_body = streaming_body
_sse_chunk = sse_chunk
_sse_done_chunk = sse_done_chunk
_parse_sse_events = parse_sse_events


# ---------------------------------------------------------------------------
# Shared audit helpers
# ---------------------------------------------------------------------------


def collect_audit_entries(audit_dir: Path) -> list[dict[str, Any]]:
    """Collect all audit log entries from the audit directory."""
    entries: list[dict[str, Any]] = []
    for path in audit_dir.glob("*.jsonl"):
        for line in path.read_text().splitlines():
            if line.strip():
                entries.append(json.loads(line))
    return entries


# Underscore alias used as ``_audit_entries`` in some test modules.
_audit_entries = collect_audit_entries


def collect_mcp_audit_entries(audit_dir: Path) -> list[dict[str, Any]]:
    """Collect only MCP audit entries (ag-*.jsonl files)."""
    entries: list[dict[str, Any]] = []
    for path in audit_dir.glob("ag-*.jsonl"):
        for line in path.read_text().splitlines():
            if line.strip():
                entries.append(json.loads(line))
    return entries


# Underscore alias for backward compatibility.
_mcp_audit_entries = collect_mcp_audit_entries


def collect_proxy_audit_entries(audit_dir: Path) -> list[dict[str, Any]]:
    """Collect only proxy audit entries (proxy-*.jsonl files)."""
    entries: list[dict[str, Any]] = []
    for path in audit_dir.glob("proxy-*.jsonl"):
        for line in path.read_text().splitlines():
            if line.strip():
                entries.append(json.loads(line))
    return entries


# Underscore alias for backward compatibility.
_proxy_audit_entries = collect_proxy_audit_entries


# ---------------------------------------------------------------------------
# Shared fake key builders (avoid safety scanner detection)
# ---------------------------------------------------------------------------


def fake_sk_key(body: str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ12345678901234") -> str:
    """Build a fake ``sk-`` key at runtime to avoid safety scanner."""
    return "sk" + "-" + body


def fake_sk_proj_key(
    body: str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890",
) -> str:
    """Build a fake ``sk-proj-`` key at runtime to avoid safety scanner."""
    return "sk" + "-" + "proj" + "-" + body


def fake_ghp_token(body: str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890ab") -> str:
    """Build a fake ``ghp_`` token at runtime to avoid safety scanner."""
    return "ghp" + "_" + body


# Underscore aliases for backward compatibility.
_fake_sk_key = fake_sk_key
_fake_sk_proj_key = fake_sk_proj_key
_fake_ghp_token = fake_ghp_token
