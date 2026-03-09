"""Tests for the proxy ASGI application factory."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
from starlette.testclient import TestClient

from agentguard.proxy.app import create_app
from agentguard.proxy.config import ProxyConfig

if TYPE_CHECKING:
    from pathlib import Path

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def config() -> ProxyConfig:
    """Create a minimal ProxyConfig."""
    return ProxyConfig(upstream_base_url="https://api.openai.com")


@pytest.fixture
def policy_dir(tmp_path: Path) -> Path:
    """Create a temp directory with an LLM request policy."""
    d = tmp_path / "policies"
    d.mkdir()
    policy = d / "block-secrets.yaml"
    policy.write_text(
        "name: block-secrets\n"
        "description: Block secrets in LLM requests\n"
        "rules:\n"
        "  - action: llm_request\n"
        "    deny:\n"
        "      - pattern: 'SECRET_VALUE'\n"
        "    severity: critical\n"
    )
    return d


# ===========================================================================
# Test: App creation
# ===========================================================================


class TestCreateApp:
    """Test the create_app factory function."""

    def test_creates_starlette_app(self, config: ProxyConfig) -> None:
        """create_app should return a Starlette application."""
        from starlette.applications import Starlette

        app = create_app(config)
        assert isinstance(app, Starlette)

    def test_app_has_middleware_on_state(self, config: ProxyConfig) -> None:
        """App should expose middleware instance on state."""
        app = create_app(config)
        assert hasattr(app.state, "middleware")
        from agentguard.proxy.middleware import GuardMiddleware

        assert isinstance(app.state.middleware, GuardMiddleware)


# ===========================================================================
# Test: Health endpoint
# ===========================================================================


class TestHealthEndpoint:
    """Test the /_health endpoint."""

    def test_health_returns_200(self, config: ProxyConfig) -> None:
        """Health endpoint should return 200 OK."""
        app = create_app(config)
        client = TestClient(app)
        response = client.get("/_health")
        assert response.status_code == 200

    def test_health_returns_status_ok(self, config: ProxyConfig) -> None:
        """Health response should contain status: ok."""
        app = create_app(config)
        client = TestClient(app)
        response = client.get("/_health")
        data = response.json()
        assert data["status"] == "ok"

    def test_health_includes_upstream(self, config: ProxyConfig) -> None:
        """Health response should include upstream URL."""
        app = create_app(config)
        client = TestClient(app)
        response = client.get("/_health")
        data = response.json()
        assert data["upstream"] == "https://api.openai.com"

    def test_health_includes_policies_loaded(self, config: ProxyConfig) -> None:
        """Health response should include policies_loaded count."""
        app = create_app(config)
        client = TestClient(app)
        response = client.get("/_health")
        data = response.json()
        assert "policies_loaded" in data
        assert data["policies_loaded"] == 0


# ===========================================================================
# Test: Status endpoint
# ===========================================================================


class TestStatusEndpoint:
    """Test the /_status endpoint."""

    def test_status_returns_200(self, config: ProxyConfig) -> None:
        """Status endpoint should return 200 OK."""
        app = create_app(config)
        client = TestClient(app)
        response = client.get("/_status")
        assert response.status_code == 200

    def test_status_includes_policy_names(self, policy_dir: Path) -> None:
        """Status should list loaded policy names."""
        config = ProxyConfig(
            upstream_base_url="https://api.openai.com",
            policy_dir=str(policy_dir),
        )
        app = create_app(config)
        client = TestClient(app)
        response = client.get("/_status")
        data = response.json()
        assert "block-secrets" in data["policy_names"]

    def test_status_includes_actor(self) -> None:
        """Status should include the configured actor name."""
        config = ProxyConfig(
            upstream_base_url="https://api.openai.com",
            actor="test-actor",
        )
        app = create_app(config)
        client = TestClient(app)
        response = client.get("/_status")
        data = response.json()
        assert data["actor"] == "test-actor"

    def test_status_includes_session_id(self, config: ProxyConfig) -> None:
        """Status should include a session ID."""
        app = create_app(config)
        client = TestClient(app)
        response = client.get("/_status")
        data = response.json()
        assert data["session_id"].startswith("proxy-")

    def test_status_includes_audit_count(self, config: ProxyConfig) -> None:
        """Status should include audit entry count."""
        app = create_app(config)
        client = TestClient(app)
        response = client.get("/_status")
        data = response.json()
        assert data["audit_entries"] == 0


# ===========================================================================
# Test: Proxy request routing
# ===========================================================================


class TestProxyRouting:
    """Test that proxy routes catch-all paths."""

    def test_arbitrary_path_is_proxied(self) -> None:
        """Any path (not /_health or /_status) should be proxied."""
        # Use a non-routable upstream to guarantee connection failure
        config = ProxyConfig(
            upstream_base_url="http://192.0.2.1:1",  # TEST-NET, always unreachable
            timeout=2.0,
        )
        app = create_app(config)
        client = TestClient(app, raise_server_exceptions=False)
        # Should attempt to proxy and get 502 (upstream unreachable), not 404
        response = client.post(
            "/v1/chat/completions",
            json={"model": "gpt-4", "messages": [{"role": "user", "content": "Hi"}]},
        )
        assert response.status_code == 502
