"""Integration tests for model routing in the proxy middleware."""

from __future__ import annotations

import json

import pytest


@pytest.fixture()
def _routing_config():
    """Create a RoutingConfig with two tiers."""
    from agentguard.proxy.routing.config import ModelTier, RoutingConfig

    return RoutingConfig(
        enabled=True,
        tiers=[
            ModelTier(
                name="fast",
                model="claude-sonnet-4",
                max_tokens=10000,
                max_messages=20,
            ),
            ModelTier(
                name="premium",
                model="claude-opus-4",
            ),
        ],
        default_tier="premium",
    )


class TestMiddlewareRouting:
    """Tests for routing integration in the middleware."""

    def test_middleware_builds_router(self, _routing_config) -> None:
        """GuardMiddleware creates a Router when routing config is set."""
        from agentguard.proxy.config import ProxyConfig
        from agentguard.proxy.middleware import GuardMiddleware
        from agentguard.proxy.routing.router import Router

        config = ProxyConfig(
            upstream_base_url="https://api.example.com",
            routing=_routing_config,
        )
        mw = GuardMiddleware(config)
        assert mw.router is not None
        assert isinstance(mw.router, Router)

    def test_middleware_no_router_without_config(self) -> None:
        """GuardMiddleware has no router when routing is not configured."""
        from agentguard.proxy.config import ProxyConfig
        from agentguard.proxy.middleware import GuardMiddleware

        config = ProxyConfig(upstream_base_url="https://api.example.com")
        mw = GuardMiddleware(config)
        assert mw.router is None

    def test_route_request_rewrites_model(self, _routing_config) -> None:
        """Routing rewrites the model field in the request body."""
        from agentguard.proxy.config import ProxyConfig
        from agentguard.proxy.middleware import GuardMiddleware

        config = ProxyConfig(
            upstream_base_url="https://api.example.com",
            routing=_routing_config,
        )
        mw = GuardMiddleware(config)

        # Small request → should route to "fast" tier → claude-sonnet-4
        body = json.dumps(
            {
                "model": "claude-opus-4",
                "messages": [
                    {"role": "user", "content": "Hello"},
                ],
            }
        ).encode()

        new_body, decision = mw._apply_routing(body)
        parsed = json.loads(new_body)

        assert decision.tier_name == "fast"
        assert decision.model == "claude-sonnet-4"
        assert parsed["model"] == "claude-sonnet-4"

    def test_route_large_request_to_premium(self, _routing_config) -> None:
        """Large requests are routed to the premium tier."""
        from agentguard.proxy.config import ProxyConfig
        from agentguard.proxy.middleware import GuardMiddleware

        config = ProxyConfig(
            upstream_base_url="https://api.example.com",
            routing=_routing_config,
        )
        mw = GuardMiddleware(config)

        # Large request — lots of messages with long content
        messages = [{"role": "user", "content": "x" * 5000} for _ in range(30)]
        body = json.dumps(
            {
                "model": "claude-sonnet-4",
                "messages": messages,
            }
        ).encode()

        new_body, decision = mw._apply_routing(body)
        parsed = json.loads(new_body)

        assert decision.tier_name == "premium"
        assert decision.model == "claude-opus-4"
        assert parsed["model"] == "claude-opus-4"

    def test_route_disabled_preserves_body(self) -> None:
        """Disabled routing preserves the original body."""
        from agentguard.proxy.config import ProxyConfig
        from agentguard.proxy.middleware import GuardMiddleware
        from agentguard.proxy.routing.config import RoutingConfig

        config = ProxyConfig(
            upstream_base_url="https://api.example.com",
            routing=RoutingConfig(enabled=False),
        )
        mw = GuardMiddleware(config)

        original = json.dumps(
            {
                "model": "original-model",
                "messages": [{"role": "user", "content": "Hello"}],
            }
        ).encode()

        new_body, decision = mw._apply_routing(original)

        assert new_body == original
        assert decision.tier_name == "passthrough"
        assert decision.model is None

    def test_route_non_json_body_passthrough(self, _routing_config) -> None:
        """Non-JSON body is passed through unchanged."""
        from agentguard.proxy.config import ProxyConfig
        from agentguard.proxy.middleware import GuardMiddleware

        config = ProxyConfig(
            upstream_base_url="https://api.example.com",
            routing=_routing_config,
        )
        mw = GuardMiddleware(config)

        body = b"not json at all"
        new_body, decision = mw._apply_routing(body)

        assert new_body == body
        assert decision.tier_name == "passthrough"

    def test_routing_audit_metadata(self, _routing_config) -> None:
        """Routing decision is included in audit metadata."""
        from agentguard.proxy.config import ProxyConfig
        from agentguard.proxy.middleware import GuardMiddleware

        config = ProxyConfig(
            upstream_base_url="https://api.example.com",
            routing=_routing_config,
        )
        mw = GuardMiddleware(config)

        body = json.dumps(
            {
                "model": "original",
                "messages": [{"role": "user", "content": "Hello"}],
            }
        ).encode()

        _, decision = mw._apply_routing(body)
        metadata = mw._routing_audit_metadata(decision)

        assert metadata["routing_tier"] == "fast"
        assert metadata["routing_model"] == "claude-sonnet-4"
        assert "routing_reason" in metadata

    def test_route_with_pattern_tier(self) -> None:
        """Pattern-based tier matches content keywords."""
        from agentguard.proxy.config import ProxyConfig
        from agentguard.proxy.middleware import GuardMiddleware
        from agentguard.proxy.routing.config import ModelTier, RoutingConfig

        routing = RoutingConfig(
            enabled=True,
            tiers=[
                ModelTier(
                    name="premium",
                    model="claude-opus-4",
                    patterns=["architect", "security.*audit"],
                ),
                ModelTier(name="standard", model="claude-sonnet-4"),
            ],
            default_tier="standard",
        )
        config = ProxyConfig(
            upstream_base_url="https://api.example.com",
            routing=routing,
        )
        mw = GuardMiddleware(config)

        # Content matches "architect"
        body = json.dumps(
            {
                "model": "original",
                "messages": [
                    {"role": "user", "content": "Help me architect a system"},
                ],
            }
        ).encode()

        _, decision = mw._apply_routing(body)
        assert decision.tier_name == "premium"
        assert decision.model == "claude-opus-4"
