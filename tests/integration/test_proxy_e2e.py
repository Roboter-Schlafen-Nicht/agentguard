"""SG-1: Proxy End-to-End (TestClient + Mock Upstream).

Integration tests that exercise the full proxy pipeline:
request → policy check → upstream → response → audit.

Uses Starlette TestClient against create_app() with mocked
upstream (via patch on middleware forward methods) to avoid
real network calls while testing real component interactions.
"""

from __future__ import annotations

from typing import TYPE_CHECKING
from unittest.mock import AsyncMock, patch

import httpx
import pytest
from starlette.testclient import TestClient

from agentguard.proxy.app import create_app
from agentguard.proxy.config import ProxyConfig

if TYPE_CHECKING:
    from pathlib import Path

pytestmark = pytest.mark.integration


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_upstream_response(
    content: str = "Hello!",
    model: str = "gpt-4",
    status_code: int = 200,
) -> httpx.Response:
    """Build a mock httpx.Response with OpenAI-format body."""
    body = {
        "id": "chatcmpl-test",
        "object": "chat.completion",
        "model": model,
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": content},
                "finish_reason": "stop",
            }
        ],
        "usage": {
            "prompt_tokens": 10,
            "completion_tokens": 20,
            "total_tokens": 30,
        },
    }
    return httpx.Response(
        status_code,
        json=body,
        headers={"content-type": "application/json"},
    )


def _chat_body(
    content: str = "Hello",
    *,
    model: str = "gpt-4",
    stream: bool = False,
) -> dict:
    """Build an OpenAI chat completions request body."""
    body: dict = {
        "model": model,
        "messages": [{"role": "user", "content": content}],
    }
    if stream:
        body["stream"] = True
    return body


# ===========================================================================
# SG-1.1: Allowed non-streaming request forwarded to upstream
# ===========================================================================


class TestAllowedRequestForwarded:
    """SG-1.1: Allowed request forwarded and audit recorded."""

    def test_allowed_request_returns_200(self) -> None:
        """Non-streaming allowed request returns upstream response."""
        config = ProxyConfig(upstream_base_url="https://api.example.com")
        app = create_app(config)
        client = TestClient(app, raise_server_exceptions=False)

        mock_resp = _make_upstream_response("Hi there!")

        with patch.object(
            app.state.middleware,
            "_forward_request",
            new_callable=AsyncMock,
            return_value=mock_resp,
        ):
            response = client.post(
                "/v1/chat/completions",
                json=_chat_body("Hello"),
            )

        assert response.status_code == 200
        data = response.json()
        assert data["choices"][0]["message"]["content"] == "Hi there!"

    def test_allowed_request_creates_audit_entry(self) -> None:
        """Allowed request creates audit entry with correct fields."""
        config = ProxyConfig(upstream_base_url="https://api.example.com")
        app = create_app(config)
        client = TestClient(app, raise_server_exceptions=False)

        mock_resp = _make_upstream_response("Hi there!")

        with patch.object(
            app.state.middleware,
            "_forward_request",
            new_callable=AsyncMock,
            return_value=mock_resp,
        ):
            client.post(
                "/v1/chat/completions",
                json=_chat_body("Hello"),
            )

        entries = app.state.middleware.audit_log.entries
        assert len(entries) == 1
        assert entries[0].action == "llm_request"
        assert entries[0].result == "allowed"
        assert entries[0].metadata is not None
        assert entries[0].metadata["upstream_status"] == "200"


# ===========================================================================
# SG-1.2: Request denied by loaded policy returns 403
# ===========================================================================


class TestDeniedRequest:
    """SG-1.2: Request denied by policy returns 403."""

    def test_denied_request_returns_403(self, deny_rm_policy_dir: Path) -> None:
        """Request matching deny policy returns 403."""
        config = ProxyConfig(
            upstream_base_url="https://api.example.com",
            policy_dir=str(deny_rm_policy_dir),
        )
        app = create_app(config)
        client = TestClient(app, raise_server_exceptions=False)

        response = client.post(
            "/v1/chat/completions",
            json=_chat_body("please run rm -rf /"),
        )

        assert response.status_code == 403
        data = response.json()
        assert data["error"] == "request denied by policy"
        assert data["denied_by"] == "deny-rm"

    def test_denied_request_audit_entry(self, deny_rm_policy_dir: Path) -> None:
        """Denied request records audit entry with denied result."""
        config = ProxyConfig(
            upstream_base_url="https://api.example.com",
            policy_dir=str(deny_rm_policy_dir),
        )
        app = create_app(config)
        client = TestClient(app, raise_server_exceptions=False)

        client.post(
            "/v1/chat/completions",
            json=_chat_body("run rm -rf / please"),
        )

        entries = app.state.middleware.audit_log.entries
        assert len(entries) == 1
        assert entries[0].result == "denied"
        assert entries[0].metadata is not None
        assert entries[0].metadata["denied_by"] == "deny-rm"


# ===========================================================================
# SG-1.3: Non-streaming response scanning (scan_responses=True)
# ===========================================================================


class TestResponseScanning:
    """SG-1.3: Response scanning denies CONFIDENTIAL content."""

    def test_response_denied_returns_403(
        self, deny_confidential_response_dir: Path
    ) -> None:
        """Response containing CONFIDENTIAL is denied (403)."""
        config = ProxyConfig(
            upstream_base_url="https://api.example.com",
            policy_dir=str(deny_confidential_response_dir),
            scan_responses=True,
        )
        app = create_app(config)
        client = TestClient(app, raise_server_exceptions=False)

        mock_resp = _make_upstream_response("CONFIDENTIAL data here")

        with patch.object(
            app.state.middleware,
            "_forward_request",
            new_callable=AsyncMock,
            return_value=mock_resp,
        ):
            response = client.post(
                "/v1/chat/completions",
                json=_chat_body("tell me a secret"),
            )

        assert response.status_code == 403
        data = response.json()
        assert data["error"] == "response denied by policy"

    def test_response_denied_creates_audit_entries(
        self, deny_confidential_response_dir: Path
    ) -> None:
        """Response denial creates 2 audit entries: request allowed, response denied."""
        config = ProxyConfig(
            upstream_base_url="https://api.example.com",
            policy_dir=str(deny_confidential_response_dir),
            scan_responses=True,
        )
        app = create_app(config)
        client = TestClient(app, raise_server_exceptions=False)

        mock_resp = _make_upstream_response("CONFIDENTIAL data here")

        with patch.object(
            app.state.middleware,
            "_forward_request",
            new_callable=AsyncMock,
            return_value=mock_resp,
        ):
            client.post(
                "/v1/chat/completions",
                json=_chat_body("tell me a secret"),
            )

        entries = app.state.middleware.audit_log.entries
        assert len(entries) == 2
        assert entries[0].action == "llm_request"
        assert entries[0].result == "allowed"
        assert entries[1].action == "llm_response"
        assert entries[1].result == "denied"


# ===========================================================================
# SG-1.3a: Response scanning allows clean responses
# ===========================================================================


class TestResponseScanningAllowsClean:
    """SG-1.3a: Clean response passes through with response scanning."""

    def test_clean_response_allowed(self, deny_confidential_response_dir: Path) -> None:
        """Clean response is forwarded with 200."""
        config = ProxyConfig(
            upstream_base_url="https://api.example.com",
            policy_dir=str(deny_confidential_response_dir),
            scan_responses=True,
        )
        app = create_app(config)
        client = TestClient(app, raise_server_exceptions=False)

        mock_resp = _make_upstream_response("Hello, how can I help?")

        with patch.object(
            app.state.middleware,
            "_forward_request",
            new_callable=AsyncMock,
            return_value=mock_resp,
        ):
            response = client.post(
                "/v1/chat/completions",
                json=_chat_body("Hi there"),
            )

        assert response.status_code == 200
        data = response.json()
        assert data["choices"][0]["message"]["content"] == "Hello, how can I help?"


# ===========================================================================
# SG-1.4: Upstream error (502) propagated with audit
# ===========================================================================


class TestUpstreamError:
    """SG-1.4: Upstream errors propagated as 502."""

    def test_upstream_error_returns_502(self) -> None:
        """Connection error returns 502."""
        config = ProxyConfig(upstream_base_url="https://api.example.com")
        app = create_app(config)
        client = TestClient(app, raise_server_exceptions=False)

        with patch.object(
            app.state.middleware,
            "_forward_request",
            new_callable=AsyncMock,
            side_effect=httpx.ConnectError("Connection refused"),
        ):
            response = client.post(
                "/v1/chat/completions",
                json=_chat_body("Hello"),
            )

        assert response.status_code == 502
        data = response.json()
        assert data["error"] == "upstream request failed"

    def test_upstream_error_audit_entry(self) -> None:
        """Connection error creates audit entry with result=error."""
        config = ProxyConfig(upstream_base_url="https://api.example.com")
        app = create_app(config)
        client = TestClient(app, raise_server_exceptions=False)

        with patch.object(
            app.state.middleware,
            "_forward_request",
            new_callable=AsyncMock,
            side_effect=httpx.ConnectError("Connection refused"),
        ):
            client.post(
                "/v1/chat/completions",
                json=_chat_body("Hello"),
            )

        entries = app.state.middleware.audit_log.entries
        assert len(entries) == 1
        assert entries[0].result == "error"
        assert entries[0].metadata is not None
        assert "error" in entries[0].metadata


# ===========================================================================
# SG-1.5: Allowed endpoints filter
# ===========================================================================


class TestAllowedEndpoints:
    """SG-1.5: Allowed endpoints filter returns 404 for unmatched paths."""

    def test_unmatched_path_returns_404(self) -> None:
        """Request to non-allowed path returns 404."""
        config = ProxyConfig(
            upstream_base_url="https://api.example.com",
            allowed_endpoints=["/v1/chat/completions"],
        )
        app = create_app(config)
        client = TestClient(app, raise_server_exceptions=False)

        response = client.post("/v1/models", json={})
        assert response.status_code == 404
        data = response.json()
        assert data["error"] == "endpoint not allowed"

    def test_matched_path_forwards(self) -> None:
        """Request to allowed path is forwarded."""
        config = ProxyConfig(
            upstream_base_url="https://api.example.com",
            allowed_endpoints=["/v1/chat/completions"],
        )
        app = create_app(config)
        client = TestClient(app, raise_server_exceptions=False)

        mock_resp = _make_upstream_response("Hello!")

        with patch.object(
            app.state.middleware,
            "_forward_request",
            new_callable=AsyncMock,
            return_value=mock_resp,
        ):
            response = client.post(
                "/v1/chat/completions",
                json=_chat_body("Hi"),
            )

        assert response.status_code == 200


# ===========================================================================
# SG-1.6: Non-JSON body passed through without scanning
# ===========================================================================


class TestNonJsonBody:
    """SG-1.6: Non-JSON body forwarded without policy check."""

    def test_non_json_passed_through(self) -> None:
        """Non-JSON body is forwarded to upstream without scanning."""
        config = ProxyConfig(upstream_base_url="https://api.example.com")
        app = create_app(config)
        client = TestClient(app, raise_server_exceptions=False)

        mock_resp = httpx.Response(200, text="OK")

        with patch.object(
            app.state.middleware,
            "_forward_request",
            new_callable=AsyncMock,
            return_value=mock_resp,
        ):
            response = client.post(
                "/v1/completions",
                content=b"this is plain text",
                headers={"content-type": "text/plain"},
            )

        assert response.status_code == 200

        # Audit entry exists with result=allowed and model=""
        entries = app.state.middleware.audit_log.entries
        assert len(entries) == 1
        assert entries[0].result == "allowed"
        assert entries[0].metadata is not None
        assert entries[0].metadata.get("model") == ""


# ===========================================================================
# SG-1.7: Health and status endpoints bypass middleware
# ===========================================================================


class TestHealthStatusEndpoints:
    """SG-1.7: /_health and /_status work without upstream."""

    def test_health_endpoint(self) -> None:
        """/_health returns status=ok, session_id, policies_loaded, upstream."""
        config = ProxyConfig(upstream_base_url="https://api.example.com")
        app = create_app(config)
        client = TestClient(app)

        response = client.get("/_health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok"
        assert "session_id" in data
        assert "policies_loaded" in data
        assert data["upstream"] == "https://api.example.com"

    def test_status_endpoint(self, deny_rm_policy_dir: Path) -> None:
        """/_status returns policy_names, audit_entries, scan_responses."""
        config = ProxyConfig(
            upstream_base_url="https://api.example.com",
            policy_dir=str(deny_rm_policy_dir),
            scan_responses=True,
        )
        app = create_app(config)
        client = TestClient(app)

        response = client.get("/_status")
        assert response.status_code == 200
        data = response.json()
        assert "deny-rm" in data["policy_names"]
        assert data["audit_entries"] == 0
        assert data["scan_responses"] is True


# ===========================================================================
# SG-1.8: Audit metadata includes message_count and token_estimate
# ===========================================================================


class TestAuditMetadata:
    """SG-1.8: Audit entries include message_count and token_estimate."""

    def test_metadata_has_message_stats(self) -> None:
        """Audit metadata contains message_count and token_estimate."""
        config = ProxyConfig(upstream_base_url="https://api.example.com")
        app = create_app(config)
        client = TestClient(app, raise_server_exceptions=False)

        mock_resp = _make_upstream_response("Hello!")

        messages = [
            {"role": "system", "content": "You are a helpful assistant."},
            {"role": "user", "content": "Tell me about Python programming."},
            {"role": "assistant", "content": "Python is a great language."},
        ]

        with patch.object(
            app.state.middleware,
            "_forward_request",
            new_callable=AsyncMock,
            return_value=mock_resp,
        ):
            client.post(
                "/v1/chat/completions",
                json={"model": "gpt-4", "messages": messages},
            )

        entries = app.state.middleware.audit_log.entries
        assert len(entries) == 1
        meta = entries[0].metadata
        assert meta is not None
        assert meta["message_count"] == "3"
        assert int(meta["token_estimate"]) > 0
