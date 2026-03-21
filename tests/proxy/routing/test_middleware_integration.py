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

    @pytest.mark.asyncio
    async def test_route_request_rewrites_model(self, _routing_config) -> None:
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

        new_body, decision = await mw._apply_routing(body)
        parsed = json.loads(new_body)

        assert decision.tier_name == "fast"
        assert decision.model == "claude-sonnet-4"
        assert parsed["model"] == "claude-sonnet-4"

    @pytest.mark.asyncio
    async def test_route_large_request_to_premium(self, _routing_config) -> None:
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

        new_body, decision = await mw._apply_routing(body)
        parsed = json.loads(new_body)

        assert decision.tier_name == "premium"
        assert decision.model == "claude-opus-4"
        assert parsed["model"] == "claude-opus-4"

    @pytest.mark.asyncio
    async def test_route_disabled_preserves_body(self) -> None:
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

        new_body, decision = await mw._apply_routing(original)

        assert new_body == original
        assert decision.tier_name == "passthrough"
        assert decision.model is None

    @pytest.mark.asyncio
    async def test_route_non_json_body_passthrough(self, _routing_config) -> None:
        """Non-JSON body is passed through unchanged."""
        from agentguard.proxy.config import ProxyConfig
        from agentguard.proxy.middleware import GuardMiddleware

        config = ProxyConfig(
            upstream_base_url="https://api.example.com",
            routing=_routing_config,
        )
        mw = GuardMiddleware(config)

        body = b"not json at all"
        new_body, decision = await mw._apply_routing(body)

        assert new_body == body
        assert decision.tier_name == "passthrough"

    @pytest.mark.asyncio
    async def test_routing_audit_metadata(self, _routing_config) -> None:
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

        _, decision = await mw._apply_routing(body)
        metadata = mw._routing_audit_metadata(decision)

        assert metadata["routing_tier"] == "fast"
        assert metadata["routing_model"] == "claude-sonnet-4"
        assert "routing_reason" in metadata

    @pytest.mark.asyncio
    async def test_route_with_pattern_tier(self) -> None:
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

        _, decision = await mw._apply_routing(body)
        assert decision.tier_name == "premium"
        assert decision.model == "claude-opus-4"


class TestMiddlewareNullModelPassthrough:
    """Tests for routing tiers with model=None (no model override)."""

    @pytest.mark.asyncio
    async def test_null_model_tier_preserves_original_model(self) -> None:
        """Tier with model=None does NOT rewrite the model field."""
        from agentguard.proxy.config import ProxyConfig
        from agentguard.proxy.middleware import GuardMiddleware
        from agentguard.proxy.routing.config import ModelTier, RoutingConfig

        routing = RoutingConfig(
            enabled=True,
            tiers=[
                ModelTier(
                    name="passthrough",
                    max_tokens=10000,
                    # No max_difficulty — not dependent on classifier
                ),
                ModelTier(name="premium", model="claude-opus-4"),
            ],
            default_tier="premium",
        )
        config = ProxyConfig(
            upstream_base_url="https://api.example.com",
            routing=routing,
        )
        mw = GuardMiddleware(config)

        body = json.dumps(
            {
                "model": "copilot-internal-model-name",
                "messages": [
                    {"role": "user", "content": "Hello"},
                ],
            }
        ).encode()

        new_body, decision = await mw._apply_routing(body)
        parsed = json.loads(new_body)

        assert decision.tier_name == "passthrough"
        assert decision.model is None
        # The original model name must be preserved
        assert parsed["model"] == "copilot-internal-model-name"

    @pytest.mark.asyncio
    async def test_all_null_model_tiers_never_rewrite(self) -> None:
        """All tiers with model=None — original model always preserved."""
        from agentguard.proxy.config import ProxyConfig
        from agentguard.proxy.middleware import GuardMiddleware
        from agentguard.proxy.routing.config import ModelTier, RoutingConfig

        routing = RoutingConfig(
            enabled=True,
            tiers=[
                ModelTier(
                    name="fast",
                    max_tokens=10000,
                    # No max_difficulty — not dependent on classifier
                ),
                ModelTier(
                    name="standard",
                    max_tokens=40000,
                    # No max_difficulty — not dependent on classifier
                ),
                ModelTier(name="premium"),
            ],
            default_tier="premium",
        )
        config = ProxyConfig(
            upstream_base_url="https://api.example.com",
            routing=routing,
        )
        mw = GuardMiddleware(config)

        body = json.dumps(
            {
                "model": "github-copilot-gpt4",
                "messages": [
                    {"role": "user", "content": "Hello"},
                ],
            }
        ).encode()

        new_body, _decision = await mw._apply_routing(body)
        parsed = json.loads(new_body)

        # Model should never be rewritten when all tiers have model=None
        assert parsed["model"] == "github-copilot-gpt4"


class TestMiddlewareClassifierWiring:
    """Tests for difficulty classifier wiring in _apply_routing."""

    @pytest.mark.asyncio
    async def test_apply_routing_calls_classifier(self) -> None:
        """_apply_routing calls classifier and passes difficulty to router."""
        from unittest.mock import AsyncMock, patch

        from agentguard.proxy.config import ProxyConfig
        from agentguard.proxy.middleware import GuardMiddleware
        from agentguard.proxy.routing.config import ModelTier, RoutingConfig

        routing = RoutingConfig(
            enabled=True,
            classifier_url="http://localhost:11435",
            tiers=[
                ModelTier(
                    name="fast",
                    max_tokens=10000,
                    max_difficulty=1,
                ),
                ModelTier(name="premium", model="claude-opus-4"),
            ],
            default_tier="premium",
        )
        config = ProxyConfig(
            upstream_base_url="https://api.example.com",
            routing=routing,
        )
        mw = GuardMiddleware(config)

        body = json.dumps(
            {
                "model": "some-model",
                "messages": [
                    {"role": "user", "content": "What is 2+2?"},
                ],
            }
        ).encode()

        # Mock the classifier to return Simple (1)
        with patch.object(mw, "_classifier", create=True) as mock_classifier:
            mock_classifier.classify = AsyncMock(return_value=1)
            _new_body, decision = await mw._apply_routing(body)

        # Classifier was called with the content
        mock_classifier.classify.assert_awaited_once()
        # Routed to fast tier because difficulty=1 <= max_difficulty=1
        assert decision.tier_name == "fast"

    @pytest.mark.asyncio
    async def test_apply_routing_without_classifier(self) -> None:
        """Without classifier_url, difficulty defaults to 0 (fail-closed).

        When no classifier is configured, difficulty=0 causes tiers
        with max_difficulty to be rejected.  The request falls through
        to the next tier without a difficulty constraint.
        """
        from agentguard.proxy.config import ProxyConfig
        from agentguard.proxy.middleware import GuardMiddleware
        from agentguard.proxy.routing.config import ModelTier, RoutingConfig

        routing = RoutingConfig(
            enabled=True,
            classifier_url="",  # No classifier
            tiers=[
                ModelTier(
                    name="fast",
                    max_tokens=10000,
                    max_difficulty=1,
                ),
                ModelTier(name="premium", model="claude-opus-4"),
            ],
            default_tier="premium",
        )
        config = ProxyConfig(
            upstream_base_url="https://api.example.com",
            routing=routing,
        )
        mw = GuardMiddleware(config)

        body = json.dumps(
            {
                "model": "some-model",
                "messages": [
                    {"role": "user", "content": "Hello"},
                ],
            }
        ).encode()

        # Without classifier, difficulty=0, so max_difficulty
        # constraint rejects fast tier → falls through to premium
        _new_body, decision = await mw._apply_routing(body)
        assert decision.tier_name == "premium"

    @pytest.mark.asyncio
    async def test_classifier_error_falls_to_premium(self) -> None:
        """Classifier error returns difficulty=0, tier with max_difficulty rejected.

        When the classifier fails (returns 0), tiers with max_difficulty
        constraints are rejected.  The request falls through to the
        premium tier — the safe direction for cost (overspend on quality
        rather than underspend on capability).
        """
        from unittest.mock import AsyncMock, patch

        from agentguard.proxy.config import ProxyConfig
        from agentguard.proxy.middleware import GuardMiddleware
        from agentguard.proxy.routing.config import ModelTier, RoutingConfig

        routing = RoutingConfig(
            enabled=True,
            classifier_url="http://localhost:11435",
            tiers=[
                ModelTier(
                    name="fast",
                    max_tokens=10000,
                    max_difficulty=1,
                ),
                ModelTier(name="premium", model="claude-opus-4"),
            ],
            default_tier="premium",
        )
        config = ProxyConfig(
            upstream_base_url="https://api.example.com",
            routing=routing,
        )
        mw = GuardMiddleware(config)

        body = json.dumps(
            {
                "model": "some-model",
                "messages": [
                    {"role": "user", "content": "Hello"},
                ],
            }
        ).encode()

        # Classifier returns 0 (fail-open)
        with patch.object(mw, "_classifier", create=True) as mock_classifier:
            mock_classifier.classify = AsyncMock(return_value=0)
            _new_body, decision = await mw._apply_routing(body)

        # difficulty=0 rejects fast tier → premium
        assert decision.tier_name == "premium"

    @pytest.mark.asyncio
    async def test_complex_request_routes_to_premium(self) -> None:
        """Classifier returns Complex (3) → fast tier rejected → premium."""
        from unittest.mock import AsyncMock, patch

        from agentguard.proxy.config import ProxyConfig
        from agentguard.proxy.middleware import GuardMiddleware
        from agentguard.proxy.routing.config import ModelTier, RoutingConfig

        routing = RoutingConfig(
            enabled=True,
            classifier_url="http://localhost:11435",
            tiers=[
                ModelTier(
                    name="fast",
                    max_tokens=10000,
                    max_difficulty=1,
                ),
                ModelTier(name="premium", model="claude-opus-4"),
            ],
            default_tier="premium",
        )
        config = ProxyConfig(
            upstream_base_url="https://api.example.com",
            routing=routing,
        )
        mw = GuardMiddleware(config)

        body = json.dumps(
            {
                "model": "some-model",
                "messages": [
                    {
                        "role": "user",
                        "content": "Design a distributed consensus algorithm",
                    },
                ],
            }
        ).encode()

        # Classifier returns Complex (3)
        with patch.object(mw, "_classifier", create=True) as mock_classifier:
            mock_classifier.classify = AsyncMock(return_value=3)
            _new_body, decision = await mw._apply_routing(body)

        # difficulty=3 > max_difficulty=1 → fast rejected → premium
        assert decision.tier_name == "premium"
        assert decision.model == "claude-opus-4"

    def test_middleware_creates_classifier_when_configured(self) -> None:
        """GuardMiddleware creates a DifficultyClassifier when URL is set."""
        from agentguard.proxy.config import ProxyConfig
        from agentguard.proxy.middleware import GuardMiddleware
        from agentguard.proxy.routing.classifier import DifficultyClassifier
        from agentguard.proxy.routing.config import ModelTier, RoutingConfig

        routing = RoutingConfig(
            enabled=True,
            classifier_url="http://localhost:11435",
            tiers=[
                ModelTier(name="default"),
            ],
            default_tier="default",
        )
        config = ProxyConfig(
            upstream_base_url="https://api.example.com",
            routing=routing,
        )
        mw = GuardMiddleware(config)

        assert hasattr(mw, "_classifier")
        assert isinstance(mw._classifier, DifficultyClassifier)

    def test_middleware_no_classifier_without_url(self) -> None:
        """GuardMiddleware has no classifier when URL is empty."""
        from agentguard.proxy.config import ProxyConfig
        from agentguard.proxy.middleware import GuardMiddleware
        from agentguard.proxy.routing.config import ModelTier, RoutingConfig

        routing = RoutingConfig(
            enabled=True,
            classifier_url="",
            tiers=[
                ModelTier(name="default", model="claude-sonnet-4"),
            ],
            default_tier="default",
        )
        config = ProxyConfig(
            upstream_base_url="https://api.example.com",
            routing=routing,
        )
        mw = GuardMiddleware(config)

        assert mw._classifier is None


class TestClassifierWindowing:
    """Tests for classifier input extraction from conversation messages.

    The classifier should only see the last human message — not tool
    call/result chatter.  In agentic sessions, the last several messages
    are typically assistant tool_use + tool results, which contain code,
    diffs, and CI logs that the classifier misclassifies as Complex.

    OpenAI format: tool results have role="tool"
    Anthropic format: tool results have role="user" + content=[{type: "tool_result"}]
    """

    @pytest.mark.asyncio
    async def test_classifier_sees_last_user_message_only(self) -> None:
        """Classifier receives only the last human user message.

        In a conversation with tool calls between user messages, the
        classifier should skip assistant and tool messages and only
        classify the most recent user message.
        """
        from unittest.mock import AsyncMock, patch

        from agentguard.proxy.config import ProxyConfig
        from agentguard.proxy.middleware import GuardMiddleware
        from agentguard.proxy.routing.config import ModelTier, RoutingConfig

        routing = RoutingConfig(
            enabled=True,
            classifier_url="http://localhost:11435",
            tiers=[
                ModelTier(name="fast", model="claude-haiku-4.5", max_difficulty=2),
                ModelTier(name="premium", model="claude-opus-4.6"),
            ],
            default_tier="premium",
        )
        config = ProxyConfig(
            upstream_base_url="https://api.example.com",
            routing=routing,
        )
        mw = GuardMiddleware(config)

        body = json.dumps(
            {
                "model": "claude-opus-4.6",
                "messages": [
                    {"role": "user", "content": "Help me architect a system"},
                    {"role": "assistant", "content": "Sure, let me run some commands"},
                    {
                        "role": "assistant",
                        "content": None,
                        "tool_calls": [
                            {
                                "id": "call_1",
                                "type": "function",
                                "function": {"name": "bash", "arguments": "{}"},
                            }
                        ],
                    },
                    {
                        "role": "tool",
                        "tool_call_id": "call_1",
                        "content": "complex output with code diffs...",
                    },
                    {
                        "role": "assistant",
                        "content": None,
                        "tool_calls": [
                            {
                                "id": "call_2",
                                "type": "function",
                                "function": {"name": "bash", "arguments": "{}"},
                            }
                        ],
                    },
                    {
                        "role": "tool",
                        "tool_call_id": "call_2",
                        "content": "more complex tool output...",
                    },
                    {"role": "user", "content": "What is 2+2?"},
                ],
            }
        ).encode()

        with patch.object(mw, "_classifier", create=True) as mock_classifier:
            mock_classifier.classify = AsyncMock(return_value=1)
            await mw._apply_routing(body)

        classified_text = mock_classifier.classify.call_args[0][0]
        # Only the last user message should be classified
        assert "What is 2+2?" in classified_text
        # Earlier messages and tool output should NOT be included
        assert "architect" not in classified_text
        assert "complex output" not in classified_text
        assert "more complex" not in classified_text

    @pytest.mark.asyncio
    async def test_classifier_skips_tool_role_messages(self) -> None:
        """Messages with role='tool' (OpenAI format) are not classified."""
        from unittest.mock import AsyncMock, patch

        from agentguard.proxy.config import ProxyConfig
        from agentguard.proxy.middleware import GuardMiddleware
        from agentguard.proxy.routing.config import ModelTier, RoutingConfig

        routing = RoutingConfig(
            enabled=True,
            classifier_url="http://localhost:11435",
            tiers=[
                ModelTier(name="fast", model="claude-haiku-4.5", max_difficulty=2),
                ModelTier(name="premium", model="claude-opus-4.6"),
            ],
            default_tier="premium",
        )
        config = ProxyConfig(
            upstream_base_url="https://api.example.com",
            routing=routing,
        )
        mw = GuardMiddleware(config)

        body = json.dumps(
            {
                "model": "claude-opus-4.6",
                "messages": [
                    {"role": "user", "content": "simple question"},
                    {
                        "role": "tool",
                        "tool_call_id": "call_1",
                        "content": "def complex_algorithm(): ...",
                    },
                ],
            }
        ).encode()

        with patch.object(mw, "_classifier", create=True) as mock_classifier:
            mock_classifier.classify = AsyncMock(return_value=1)
            await mw._apply_routing(body)

        classified_text = mock_classifier.classify.call_args[0][0]
        assert "simple question" in classified_text
        assert "complex_algorithm" not in classified_text

    @pytest.mark.asyncio
    async def test_classifier_skips_anthropic_tool_result(self) -> None:
        """Anthropic-format tool_result messages are not classified.

        Anthropic sends tool results as role='user' with content
        containing {type: 'tool_result'} blocks.  These should be
        skipped — only real human text messages count.
        """
        from unittest.mock import AsyncMock, patch

        from agentguard.proxy.config import ProxyConfig
        from agentguard.proxy.middleware import GuardMiddleware
        from agentguard.proxy.routing.config import ModelTier, RoutingConfig

        routing = RoutingConfig(
            enabled=True,
            classifier_url="http://localhost:11435",
            tiers=[
                ModelTier(name="fast", model="claude-haiku-4.5", max_difficulty=2),
                ModelTier(name="premium", model="claude-opus-4.6"),
            ],
            default_tier="premium",
        )
        config = ProxyConfig(
            upstream_base_url="https://api.example.com",
            routing=routing,
        )
        mw = GuardMiddleware(config)

        body = json.dumps(
            {
                "model": "claude-opus-4.6",
                "messages": [
                    {"role": "user", "content": "How do I sort a list?"},
                    {
                        "role": "assistant",
                        "content": [
                            {
                                "type": "tool_use",
                                "id": "toolu_1",
                                "name": "bash",
                                "input": {"command": "echo"},
                            }
                        ],
                    },
                    {
                        "role": "user",
                        "content": [
                            {
                                "type": "tool_result",
                                "tool_use_id": "toolu_1",
                                "content": "complex system output",
                            }
                        ],
                    },
                    {"role": "user", "content": "Thanks, looks good"},
                ],
            }
        ).encode()

        with patch.object(mw, "_classifier", create=True) as mock_classifier:
            mock_classifier.classify = AsyncMock(return_value=1)
            await mw._apply_routing(body)

        classified_text = mock_classifier.classify.call_args[0][0]
        # Last real user message
        assert "Thanks, looks good" in classified_text
        # Tool result content should NOT be included
        assert "complex system output" not in classified_text

    @pytest.mark.asyncio
    async def test_classifier_with_only_tool_messages_at_end(self) -> None:
        """When conversation ends in tool calls, classify last user msg."""
        from unittest.mock import AsyncMock, patch

        from agentguard.proxy.config import ProxyConfig
        from agentguard.proxy.middleware import GuardMiddleware
        from agentguard.proxy.routing.config import ModelTier, RoutingConfig

        routing = RoutingConfig(
            enabled=True,
            classifier_url="http://localhost:11435",
            tiers=[
                ModelTier(name="fast", model="claude-haiku-4.5", max_difficulty=2),
                ModelTier(name="premium", model="claude-opus-4.6"),
            ],
            default_tier="premium",
        )
        config = ProxyConfig(
            upstream_base_url="https://api.example.com",
            routing=routing,
        )
        mw = GuardMiddleware(config)

        body = json.dumps(
            {
                "model": "claude-opus-4.6",
                "messages": [
                    {"role": "user", "content": "Run the tests please"},
                    {
                        "role": "assistant",
                        "content": None,
                        "tool_calls": [
                            {
                                "id": "call_1",
                                "type": "function",
                                "function": {"name": "bash", "arguments": "{}"},
                            }
                        ],
                    },
                    {
                        "role": "tool",
                        "tool_call_id": "call_1",
                        "content": "PASSED 1874 tests in 45.2s",
                    },
                    {
                        "role": "assistant",
                        "content": None,
                        "tool_calls": [
                            {
                                "id": "call_2",
                                "type": "function",
                                "function": {"name": "bash", "arguments": "{}"},
                            }
                        ],
                    },
                    {
                        "role": "tool",
                        "tool_call_id": "call_2",
                        "content": "git commit -m 'fix: something'",
                    },
                ],
            }
        ).encode()

        with patch.object(mw, "_classifier", create=True) as mock_classifier:
            mock_classifier.classify = AsyncMock(return_value=1)
            await mw._apply_routing(body)

        classified_text = mock_classifier.classify.call_args[0][0]
        # Should find the user message before the tool calls
        assert "Run the tests please" in classified_text
        # Tool output should not be included
        assert "PASSED 1874" not in classified_text
        assert "git commit" not in classified_text

    @pytest.mark.asyncio
    async def test_classifier_no_user_messages_uses_empty(self) -> None:
        """If no user messages exist, classifier gets empty string."""
        from unittest.mock import AsyncMock, patch

        from agentguard.proxy.config import ProxyConfig
        from agentguard.proxy.middleware import GuardMiddleware
        from agentguard.proxy.routing.config import ModelTier, RoutingConfig

        routing = RoutingConfig(
            enabled=True,
            classifier_url="http://localhost:11435",
            tiers=[
                ModelTier(name="fast", model="claude-haiku-4.5", max_difficulty=2),
                ModelTier(name="premium", model="claude-opus-4.6"),
            ],
            default_tier="premium",
        )
        config = ProxyConfig(
            upstream_base_url="https://api.example.com",
            routing=routing,
        )
        mw = GuardMiddleware(config)

        body = json.dumps(
            {
                "model": "claude-opus-4.6",
                "messages": [
                    {"role": "system", "content": "You are a helpful assistant"},
                    {"role": "assistant", "content": "Hello!"},
                ],
            }
        ).encode()

        with patch.object(mw, "_classifier", create=True) as mock_classifier:
            mock_classifier.classify = AsyncMock(return_value=0)
            await mw._apply_routing(body)

        classified_text = mock_classifier.classify.call_args[0][0]
        assert classified_text == ""

    @pytest.mark.asyncio
    async def test_router_still_gets_full_content(self) -> None:
        """Router receives ALL content for token estimation and patterns.

        The classifier only sees the last user message, but the router
        still gets full content for token estimation, pattern matching,
        and message count.
        """
        from unittest.mock import AsyncMock, patch

        from agentguard.proxy.config import ProxyConfig
        from agentguard.proxy.middleware import GuardMiddleware
        from agentguard.proxy.routing.config import ModelTier, RoutingConfig

        routing = RoutingConfig(
            enabled=True,
            classifier_url="http://localhost:11435",
            tiers=[
                ModelTier(
                    name="pattern-match",
                    model="claude-opus-4.6",
                    patterns=["architect"],
                ),
                ModelTier(name="default", model="claude-haiku-4.5"),
            ],
            default_tier="default",
        )
        config = ProxyConfig(
            upstream_base_url="https://api.example.com",
            routing=routing,
        )
        mw = GuardMiddleware(config)

        body = json.dumps(
            {
                "model": "claude-opus-4.6",
                "messages": [
                    {"role": "user", "content": "Help me architect a system"},
                    {"role": "assistant", "content": "Sure, here is the plan"},
                    {"role": "user", "content": "Looks good"},
                ],
            }
        ).encode()

        with patch.object(mw, "_classifier", create=True) as mock_classifier:
            mock_classifier.classify = AsyncMock(return_value=1)
            _, decision = await mw._apply_routing(body)

        # Pattern "architect" is in message 1 (not the last user msg)
        # but the router sees ALL content, so pattern match should work
        assert decision.tier_name == "pattern-match"
