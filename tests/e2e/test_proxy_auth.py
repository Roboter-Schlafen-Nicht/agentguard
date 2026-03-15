"""E2E tests: Proxy auth injection and upstream forwarding (SG-5).

CRITICAL — This is the feature that failed in production. These tests
exercise the full proxy stack with auth injection through a real Starlette
app and mock upstream, validating that credentials are correctly injected,
error cases are handled gracefully, and upstream failures are properly
audited.

Test matrix:
    SG-5.1  Auth token injected from auth.json (replaces client token)
    SG-5.2  Refresh field used for OAuth tokens
    SG-5.3  Key field fallback for API keys
    SG-5.4  Missing auth.json — no crash, client token preserved
    SG-5.5  Malformed auth.json — ValueError at startup
    SG-5.6  Missing provider key — ValueError at startup
    SG-5.7  Token NOT hot-reloaded (known issue #88)
    SG-5.8  Upstream failure produces audit entry
    SG-5.9  Non-200 upstream status forwarded to client
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

import httpx
import pytest

from agentguard.proxy.app import create_app
from agentguard.proxy.config import ProxyConfig
from tests.e2e.conftest import (
    _chat_body,
    _create_proxy,
)

if TYPE_CHECKING:
    from pathlib import Path

    from tests.e2e.conftest import MockUpstream


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _write_auth_file(path: Path, data: Any) -> Path:
    """Write auth data to a JSON file and return the path."""
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


# ---------------------------------------------------------------------------
# SG-5.1: Auth token injected from auth.json (replaces client token)
# ---------------------------------------------------------------------------


@pytest.mark.anyio
async def test_auth_token_replaces_client_header(
    mock_upstream: MockUpstream,
    tmp_path: Path,
    audit_dir: Path,
) -> None:
    """The proxy replaces the client's Authorization header with the
    token from auth.json.  The upstream should never see the client's
    original token.
    """
    auth_path = _write_auth_file(
        tmp_path / "auth.json",
        {"github-copilot": {"refresh": "injected-server-token"}},
    )
    app = _create_proxy(
        mock_upstream,
        audit_dir,
        load_builtins=True,
        scan_responses=True,
        auth_file=str(auth_path),
    )

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://proxy",
    ) as client:
        resp = await client.post(
            "/v1/chat/completions",
            json=_chat_body(),
            headers={"Authorization": "Bearer client-original-token"},
        )

    assert resp.status_code == 200
    assert len(mock_upstream.requests) == 1
    upstream_auth = mock_upstream.requests[0]["headers"]["authorization"]
    assert upstream_auth == "Bearer injected-server-token"
    assert "client-original-token" not in upstream_auth


# ---------------------------------------------------------------------------
# SG-5.2: Refresh field used for OAuth tokens
# ---------------------------------------------------------------------------


@pytest.mark.anyio
async def test_refresh_field_used_for_oauth(
    mock_upstream: MockUpstream,
    tmp_path: Path,
    audit_dir: Path,
) -> None:
    """When both 'refresh' and 'key' are present, 'refresh' takes
    priority (OAuth flow).
    """
    auth_path = _write_auth_file(
        tmp_path / "auth.json",
        {
            "github-copilot": {
                "type": "oauth",
                "refresh": "gho_refresh_token",
                "key": "should-not-be-used",
            }
        },
    )
    app = _create_proxy(
        mock_upstream,
        audit_dir,
        load_builtins=True,
        scan_responses=True,
        auth_file=str(auth_path),
    )

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://proxy",
    ) as client:
        resp = await client.post(
            "/v1/chat/completions",
            json=_chat_body(),
        )

    assert resp.status_code == 200
    upstream_auth = mock_upstream.requests[0]["headers"]["authorization"]
    assert upstream_auth == "Bearer gho_refresh_token"


# ---------------------------------------------------------------------------
# SG-5.3: Key field fallback for API keys
# ---------------------------------------------------------------------------


@pytest.mark.anyio
async def test_key_field_fallback(
    mock_upstream: MockUpstream,
    tmp_path: Path,
    audit_dir: Path,
) -> None:
    """When only 'key' is present (no 'refresh'), the key field is used."""
    auth_path = _write_auth_file(
        tmp_path / "auth.json",
        {"anthropic": {"type": "api", "key": "sk-ant-api-key"}},
    )
    app = _create_proxy(
        mock_upstream,
        audit_dir,
        load_builtins=True,
        scan_responses=True,
        auth_file=str(auth_path),
        auth_provider="anthropic",
    )

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://proxy",
    ) as client:
        resp = await client.post(
            "/v1/chat/completions",
            json=_chat_body(),
        )

    assert resp.status_code == 200
    upstream_auth = mock_upstream.requests[0]["headers"]["authorization"]
    assert upstream_auth == "Bearer sk-ant-api-key"


# ---------------------------------------------------------------------------
# SG-5.4: Missing auth.json — no crash, client token preserved
# ---------------------------------------------------------------------------


@pytest.mark.anyio
async def test_no_auth_file_preserves_client_token(
    mock_upstream: MockUpstream,
    audit_dir: Path,
) -> None:
    """Without auth_file configured, the client's original Authorization
    header is forwarded to the upstream unchanged.
    """
    app = _create_proxy(
        mock_upstream,
        audit_dir,
        load_builtins=True,
        scan_responses=True,
        auth_file=None,
    )

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://proxy",
    ) as client:
        resp = await client.post(
            "/v1/chat/completions",
            json=_chat_body(),
            headers={"Authorization": "Bearer client-token-passthrough"},
        )

    assert resp.status_code == 200
    upstream_auth = mock_upstream.requests[0]["headers"]["authorization"]
    assert upstream_auth == "Bearer client-token-passthrough"


# ---------------------------------------------------------------------------
# SG-5.5: Malformed auth.json — ValueError at startup
# ---------------------------------------------------------------------------


def test_malformed_auth_json_raises(tmp_path: Path) -> None:
    """A malformed auth.json file raises ValueError during middleware
    construction, preventing the proxy from starting with bad credentials.

    ProxyConfig only validates file existence.  The ValueError is raised
    by GuardMiddleware._load_auth_token inside create_app.
    """
    auth_path = tmp_path / "auth.json"
    auth_path.write_text("{not valid json!!!", encoding="utf-8")

    with pytest.raises(ValueError, match="Invalid JSON"):
        create_app(
            ProxyConfig(
                upstream_base_url="http://example.com",
                auth_file=str(auth_path),
            )
        )


# ---------------------------------------------------------------------------
# SG-5.6: Missing provider key — ValueError at startup
# ---------------------------------------------------------------------------


def test_missing_provider_key_raises(tmp_path: Path) -> None:
    """When the auth.json file doesn't contain the configured provider key,
    the middleware raises ValueError at startup.
    """
    auth_path = _write_auth_file(
        tmp_path / "auth.json",
        {"openai": {"key": "sk-openai-key"}},
    )

    with pytest.raises(ValueError, match="not found"):
        create_app(
            ProxyConfig(
                upstream_base_url="http://example.com",
                auth_file=str(auth_path),
                auth_provider="github-copilot",  # not in file
            )
        )


# ---------------------------------------------------------------------------
# SG-5.7: Token NOT hot-reloaded (known issue #88)
# ---------------------------------------------------------------------------


@pytest.mark.anyio
async def test_token_not_hot_reloaded(
    mock_upstream: MockUpstream,
    tmp_path: Path,
    audit_dir: Path,
) -> None:
    """The auth token is loaded once at startup and NOT reloaded when the
    file changes.  This is a known limitation (issue #88).

    This test verifies the current behavior: even after updating
    auth.json, the proxy continues to use the original token.
    """
    auth_path = _write_auth_file(
        tmp_path / "auth.json",
        {"github-copilot": {"refresh": "original-token"}},
    )
    app = _create_proxy(
        mock_upstream,
        audit_dir,
        load_builtins=True,
        scan_responses=True,
        auth_file=str(auth_path),
    )

    transport = httpx.ASGITransport(app=app)

    # First request — uses original token
    async with httpx.AsyncClient(
        transport=transport, base_url="http://proxy"
    ) as client:
        await client.post("/v1/chat/completions", json=_chat_body())

    assert mock_upstream.requests[0]["headers"]["authorization"] == (
        "Bearer original-token"
    )

    # Update the file on disk
    _write_auth_file(auth_path, {"github-copilot": {"refresh": "updated-token"}})

    # Second request — still uses original token (NOT hot-reloaded)
    async with httpx.AsyncClient(
        transport=transport, base_url="http://proxy"
    ) as client:
        await client.post("/v1/chat/completions", json=_chat_body())

    assert mock_upstream.requests[1]["headers"]["authorization"] == (
        "Bearer original-token"
    )
    assert mock_upstream.requests[1]["headers"]["authorization"] != (
        "Bearer updated-token"
    )


# ---------------------------------------------------------------------------
# SG-5.8: Upstream failure produces audit entry
# ---------------------------------------------------------------------------


@pytest.mark.anyio
async def test_upstream_failure_audit_entry(
    mock_upstream: MockUpstream,
    tmp_path: Path,
) -> None:
    """When the upstream request fails (e.g. connection error), the proxy
    returns 502 and records an 'error' audit entry.
    """
    audit_dir = tmp_path / "audit"
    audit_dir.mkdir(exist_ok=True)

    config = ProxyConfig(
        upstream_base_url="http://mock-upstream",
        audit_dir=str(audit_dir),
        load_builtins=True,
    )
    app = create_app(config)
    middleware = app.state.middleware

    # Patch forwarding to raise an HTTP error
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
        transport=httpx.ASGITransport(app=app),
        base_url="http://proxy",
    ) as client:
        resp = await client.post(
            "/v1/chat/completions",
            json=_chat_body(),
        )

    assert resp.status_code == 502
    error_data = resp.json()
    assert error_data["error"] == "upstream request failed"
    assert "Connection refused" in error_data["detail"]

    # Verify audit log recorded the error
    middleware._save_audit()
    audit_files = list(audit_dir.glob("*.jsonl"))
    assert len(audit_files) >= 1

    all_entries: list[dict[str, Any]] = []
    for af in audit_files:
        for line in af.read_text().splitlines():
            if line.strip():
                all_entries.append(json.loads(line))

    error_entries = [e for e in all_entries if e.get("result") == "error"]
    assert len(error_entries) >= 1
    assert "Connection refused" in error_entries[0].get("metadata", {}).get("error", "")


# ---------------------------------------------------------------------------
# SG-5.9: Non-200 upstream status forwarded to client
# ---------------------------------------------------------------------------


@pytest.mark.anyio
async def test_non_200_upstream_forwarded(
    mock_upstream: MockUpstream,
    audit_dir: Path,
) -> None:
    """When the upstream returns a non-200 status (e.g. 429 rate limit),
    the proxy forwards the status code and body to the client.
    """
    mock_upstream.set_response(
        {"error": {"message": "Rate limit exceeded", "type": "rate_limit_error"}},
        status=429,
    )

    app = _create_proxy(
        mock_upstream,
        audit_dir,
        load_builtins=True,
        scan_responses=True,
        auth_file=None,
    )

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://proxy",
    ) as client:
        resp = await client.post(
            "/v1/chat/completions",
            json=_chat_body(),
        )

    assert resp.status_code == 429
    body = resp.json()
    assert body["error"]["message"] == "Rate limit exceeded"
    assert body["error"]["type"] == "rate_limit_error"
