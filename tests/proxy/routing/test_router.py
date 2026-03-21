"""Tests for the Router class."""

from __future__ import annotations

import pytest


class TestRoutingDecision:
    """Tests for RoutingDecision dataclass."""

    def test_routing_decision_fields(self) -> None:
        """RoutingDecision has expected fields."""
        from agentguard.proxy.routing.router import RoutingDecision

        decision = RoutingDecision(
            tier_name="fast",
            model="claude-sonnet-4",
            upstream_url=None,
            reason="token_count <= 10000",
        )
        assert decision.tier_name == "fast"
        assert decision.model == "claude-sonnet-4"
        assert decision.upstream_url is None
        assert decision.reason == "token_count <= 10000"

    def test_routing_decision_is_frozen(self) -> None:
        """RoutingDecision is immutable."""
        from agentguard.proxy.routing.router import RoutingDecision

        decision = RoutingDecision(
            tier_name="fast",
            model="claude-sonnet-4",
            upstream_url=None,
            reason="test",
        )
        with pytest.raises(AttributeError):
            decision.tier_name = "premium"  # type: ignore[misc]


class TestRouterDisabled:
    """Tests for Router when routing is disabled."""

    def test_disabled_returns_passthrough(self) -> None:
        """Disabled router returns passthrough decision."""
        from agentguard.proxy.routing.config import RoutingConfig
        from agentguard.proxy.routing.router import Router

        config = RoutingConfig(enabled=False)
        router = Router(config)

        decision = router.route(
            token_estimate=1000,
            message_count=5,
            content="Hello world",
        )

        assert decision.tier_name == "passthrough"
        assert decision.model is None
        assert decision.upstream_url is None
        assert "disabled" in decision.reason.lower()


class TestRouterTokenMatching:
    """Tests for Router token-based tier matching."""

    def test_matches_tier_by_token_count(self) -> None:
        """Router matches tier when token count is within max_tokens."""
        from agentguard.proxy.routing.config import ModelTier, RoutingConfig
        from agentguard.proxy.routing.router import Router

        config = RoutingConfig(
            enabled=True,
            tiers=[
                ModelTier(name="fast", model="claude-sonnet-4", max_tokens=10000),
                ModelTier(name="premium", model="claude-opus-4"),
            ],
            default_tier="premium",
        )
        router = Router(config)

        # Under threshold — matches fast tier
        decision = router.route(token_estimate=5000, message_count=10, content="")
        assert decision.tier_name == "fast"
        assert decision.model == "claude-sonnet-4"

    def test_exceeds_token_threshold_falls_through(self) -> None:
        """Router falls through when token count exceeds max_tokens."""
        from agentguard.proxy.routing.config import ModelTier, RoutingConfig
        from agentguard.proxy.routing.router import Router

        config = RoutingConfig(
            enabled=True,
            tiers=[
                ModelTier(name="fast", model="claude-sonnet-4", max_tokens=10000),
                ModelTier(name="premium", model="claude-opus-4"),
            ],
            default_tier="premium",
        )
        router = Router(config)

        # Over threshold — falls through to premium (no max_tokens constraint)
        decision = router.route(token_estimate=15000, message_count=10, content="")
        assert decision.tier_name == "premium"
        assert decision.model == "claude-opus-4"


class TestRouterMessageMatching:
    """Tests for Router message-count-based tier matching."""

    def test_matches_tier_by_message_count(self) -> None:
        """Router matches tier when message count is within max_messages."""
        from agentguard.proxy.routing.config import ModelTier, RoutingConfig
        from agentguard.proxy.routing.router import Router

        config = RoutingConfig(
            enabled=True,
            tiers=[
                ModelTier(name="simple", model="gpt-4o-mini", max_messages=5),
                ModelTier(name="standard", model="gpt-4o"),
            ],
            default_tier="standard",
        )
        router = Router(config)

        decision = router.route(token_estimate=1000, message_count=3, content="")
        assert decision.tier_name == "simple"
        assert decision.model == "gpt-4o-mini"

    def test_exceeds_message_threshold_falls_through(self) -> None:
        """Router falls through when message count exceeds max_messages."""
        from agentguard.proxy.routing.config import ModelTier, RoutingConfig
        from agentguard.proxy.routing.router import Router

        config = RoutingConfig(
            enabled=True,
            tiers=[
                ModelTier(name="simple", model="gpt-4o-mini", max_messages=5),
                ModelTier(name="standard", model="gpt-4o"),
            ],
            default_tier="standard",
        )
        router = Router(config)

        decision = router.route(token_estimate=1000, message_count=10, content="")
        assert decision.tier_name == "standard"
        assert decision.model == "gpt-4o"


class TestRouterCombinedConstraints:
    """Tests for Router with combined token and message constraints."""

    def test_both_constraints_must_match(self) -> None:
        """Tier with both max_tokens and max_messages requires both to match."""
        from agentguard.proxy.routing.config import ModelTier, RoutingConfig
        from agentguard.proxy.routing.router import Router

        config = RoutingConfig(
            enabled=True,
            tiers=[
                ModelTier(
                    name="fast",
                    model="claude-sonnet-4",
                    max_tokens=10000,
                    max_messages=20,
                ),
                ModelTier(name="premium", model="claude-opus-4"),
            ],
            default_tier="premium",
        )
        router = Router(config)

        # Both under threshold — matches fast
        decision = router.route(token_estimate=5000, message_count=10, content="")
        assert decision.tier_name == "fast"

        # Tokens under, messages over — falls through
        decision = router.route(token_estimate=5000, message_count=30, content="")
        assert decision.tier_name == "premium"

        # Tokens over, messages under — falls through
        decision = router.route(token_estimate=15000, message_count=10, content="")
        assert decision.tier_name == "premium"


class TestRouterPatternMatching:
    """Tests for Router pattern-based tier matching."""

    def test_matches_tier_by_content_pattern(self) -> None:
        """Router matches tier when content matches a pattern."""
        from agentguard.proxy.routing.config import ModelTier, RoutingConfig
        from agentguard.proxy.routing.router import Router

        config = RoutingConfig(
            enabled=True,
            tiers=[
                ModelTier(
                    name="premium",
                    model="claude-opus-4",
                    patterns=["architect", "complex.*design"],
                ),
                ModelTier(name="standard", model="claude-sonnet-4"),
            ],
            default_tier="standard",
        )
        router = Router(config)

        # Content matches "architect" pattern
        decision = router.route(
            token_estimate=1000,
            message_count=5,
            content="Please help me architect a microservices system",
        )
        assert decision.tier_name == "premium"
        assert decision.model == "claude-opus-4"

    def test_pattern_is_case_insensitive(self) -> None:
        """Pattern matching is case-insensitive."""
        from agentguard.proxy.routing.config import ModelTier, RoutingConfig
        from agentguard.proxy.routing.router import Router

        config = RoutingConfig(
            enabled=True,
            tiers=[
                ModelTier(name="premium", model="claude-opus-4", patterns=["URGENT"]),
                ModelTier(name="standard", model="claude-sonnet-4"),
            ],
            default_tier="standard",
        )
        router = Router(config)

        decision = router.route(
            token_estimate=1000,
            message_count=5,
            content="This is urgent please help",
        )
        assert decision.tier_name == "premium"

    def test_no_pattern_match_falls_through(self) -> None:
        """No pattern match falls through to next tier."""
        from agentguard.proxy.routing.config import ModelTier, RoutingConfig
        from agentguard.proxy.routing.router import Router

        config = RoutingConfig(
            enabled=True,
            tiers=[
                ModelTier(
                    name="premium", model="claude-opus-4", patterns=["architect"]
                ),
                ModelTier(name="standard", model="claude-sonnet-4"),
            ],
            default_tier="standard",
        )
        router = Router(config)

        decision = router.route(
            token_estimate=1000,
            message_count=5,
            content="Hello, how are you?",
        )
        assert decision.tier_name == "standard"


class TestRouterDefaultTier:
    """Tests for Router default tier fallback."""

    def test_falls_back_to_default_tier(self) -> None:
        """Router falls back to default tier when no tiers match."""
        from agentguard.proxy.routing.config import ModelTier, RoutingConfig
        from agentguard.proxy.routing.router import Router

        config = RoutingConfig(
            enabled=True,
            tiers=[
                ModelTier(name="fast", model="claude-sonnet-4", max_tokens=1000),
            ],
            default_tier="fast",
        )
        router = Router(config)

        # Exceeds all thresholds — falls back to default
        decision = router.route(token_estimate=50000, message_count=100, content="")
        assert decision.tier_name == "fast"
        assert "default" in decision.reason.lower()

    def test_default_tier_not_found_uses_last_tier(self) -> None:
        """If default_tier doesn't match any tier name, use last tier."""
        from agentguard.proxy.routing.config import ModelTier, RoutingConfig
        from agentguard.proxy.routing.router import Router

        config = RoutingConfig(
            enabled=True,
            tiers=[
                ModelTier(name="fast", model="claude-sonnet-4", max_tokens=1000),
                ModelTier(name="premium", model="claude-opus-4"),
            ],
            default_tier="nonexistent",
        )
        router = Router(config)

        decision = router.route(token_estimate=50000, message_count=100, content="")
        # Falls back to last tier since default doesn't exist
        assert decision.tier_name == "premium"


class TestRouterUpstreamOverride:
    """Tests for Router upstream URL override."""

    def test_returns_upstream_url_from_tier(self) -> None:
        """Router returns upstream_url from matched tier."""
        from agentguard.proxy.routing.config import ModelTier, RoutingConfig
        from agentguard.proxy.routing.router import Router

        config = RoutingConfig(
            enabled=True,
            tiers=[
                ModelTier(
                    name="anthropic",
                    model="claude-opus-4",
                    upstream_url="https://api.anthropic.com",
                    patterns=["anthropic"],
                ),
                ModelTier(name="default", model="gpt-4o"),
            ],
            default_tier="default",
        )
        router = Router(config)

        decision = router.route(
            token_estimate=1000,
            message_count=5,
            content="Use anthropic for this",
        )
        assert decision.tier_name == "anthropic"
        assert decision.upstream_url == "https://api.anthropic.com"


class TestRouterNullModelPassthrough:
    """Tests for Router with model=None tiers (no model override)."""

    def test_null_model_tier_returns_none_model(self) -> None:
        """Tier with model=None returns decision.model=None."""
        from agentguard.proxy.routing.config import ModelTier, RoutingConfig
        from agentguard.proxy.routing.router import Router

        config = RoutingConfig(
            enabled=True,
            tiers=[
                ModelTier(
                    name="passthrough",
                    max_tokens=10000,
                    max_difficulty=1,
                ),
                ModelTier(name="premium", model="claude-opus-4"),
            ],
            default_tier="premium",
        )
        router = Router(config)

        decision = router.route(
            token_estimate=5000,
            message_count=5,
            content="",
            difficulty=1,
        )
        assert decision.tier_name == "passthrough"
        assert decision.model is None

    def test_null_model_falls_through_to_model_tier(self) -> None:
        """When null-model tier doesn't match, falls to tier with model."""
        from agentguard.proxy.routing.config import ModelTier, RoutingConfig
        from agentguard.proxy.routing.router import Router

        config = RoutingConfig(
            enabled=True,
            tiers=[
                ModelTier(
                    name="passthrough",
                    max_tokens=10000,
                    max_difficulty=1,
                ),
                ModelTier(name="premium", model="claude-opus-4"),
            ],
            default_tier="premium",
        )
        router = Router(config)

        # difficulty=3 exceeds passthrough max_difficulty=1
        decision = router.route(
            token_estimate=5000,
            message_count=5,
            content="",
            difficulty=3,
        )
        assert decision.tier_name == "premium"
        assert decision.model == "claude-opus-4"

    def test_all_tiers_null_model(self) -> None:
        """All tiers with model=None — no model override ever happens."""
        from agentguard.proxy.routing.config import ModelTier, RoutingConfig
        from agentguard.proxy.routing.router import Router

        config = RoutingConfig(
            enabled=True,
            tiers=[
                ModelTier(
                    name="fast",
                    max_tokens=10000,
                    max_difficulty=1,
                ),
                ModelTier(
                    name="standard",
                    max_tokens=40000,
                    max_difficulty=2,
                ),
                ModelTier(name="premium"),
            ],
            default_tier="premium",
        )
        router = Router(config)

        for diff in [1, 2, 3]:
            decision = router.route(
                token_estimate=5000,
                message_count=5,
                content="",
                difficulty=diff,
            )
            assert decision.model is None, (
                f"difficulty={diff}: expected model=None, got model={decision.model}"
            )


class TestRouterTierOrder:
    """Tests for Router tier evaluation order."""

    def test_first_matching_tier_wins(self) -> None:
        """Router uses first matching tier when multiple could match."""
        from agentguard.proxy.routing.config import ModelTier, RoutingConfig
        from agentguard.proxy.routing.router import Router

        config = RoutingConfig(
            enabled=True,
            tiers=[
                ModelTier(name="first", model="model-a", max_tokens=10000),
                ModelTier(name="second", model="model-b", max_tokens=20000),
                ModelTier(name="third", model="model-c"),
            ],
            default_tier="third",
        )
        router = Router(config)

        # 5000 tokens matches both first and second, should use first
        decision = router.route(token_estimate=5000, message_count=5, content="")
        assert decision.tier_name == "first"
        assert decision.model == "model-a"


class TestRouterDifficultyMatching:
    """Tests for Router difficulty-based tier matching."""

    def test_matches_tier_by_difficulty(self) -> None:
        """Router matches tier when difficulty is within max_difficulty."""
        from agentguard.proxy.routing.config import ModelTier, RoutingConfig
        from agentguard.proxy.routing.router import Router

        config = RoutingConfig(
            enabled=True,
            tiers=[
                ModelTier(
                    name="fast",
                    model="claude-sonnet-4",
                    max_difficulty=1,
                ),
                ModelTier(name="premium", model="claude-opus-4"),
            ],
            default_tier="premium",
        )
        router = Router(config)

        # difficulty=1 (Simple) — matches fast tier
        decision = router.route(
            token_estimate=1000,
            message_count=5,
            content="",
            difficulty=1,
        )
        assert decision.tier_name == "fast"
        assert decision.model == "claude-sonnet-4"

    def test_exceeds_difficulty_falls_through(self) -> None:
        """Router falls through when difficulty exceeds max_difficulty."""
        from agentguard.proxy.routing.config import ModelTier, RoutingConfig
        from agentguard.proxy.routing.router import Router

        config = RoutingConfig(
            enabled=True,
            tiers=[
                ModelTier(
                    name="fast",
                    model="claude-sonnet-4",
                    max_difficulty=1,
                ),
                ModelTier(name="premium", model="claude-opus-4"),
            ],
            default_tier="premium",
        )
        router = Router(config)

        # difficulty=3 (Complex) — falls through to premium
        decision = router.route(
            token_estimate=1000,
            message_count=5,
            content="",
            difficulty=3,
        )
        assert decision.tier_name == "premium"
        assert decision.model == "claude-opus-4"

    def test_difficulty_zero_rejects_tier_with_max_difficulty(self) -> None:
        """difficulty=0 (unknown) does NOT match a tier with max_difficulty.

        When the classifier fails or is unavailable (difficulty=0),
        tiers that rely on difficulty constraints must be skipped.
        This ensures complex requests fall through to the premium
        tier rather than being routed to a cheap model by accident.
        """
        from agentguard.proxy.routing.config import ModelTier, RoutingConfig
        from agentguard.proxy.routing.router import Router

        config = RoutingConfig(
            enabled=True,
            tiers=[
                ModelTier(
                    name="fast",
                    model="claude-haiku-4.5",
                    max_difficulty=2,
                ),
                ModelTier(name="premium", model="claude-opus-4.6"),
            ],
            default_tier="premium",
        )
        router = Router(config)

        # difficulty=0 (unknown/classifier failure) — fast tier has
        # max_difficulty so it must NOT match; falls through to premium
        decision = router.route(
            token_estimate=1000,
            message_count=5,
            content="",
            difficulty=0,
        )
        assert decision.tier_name == "premium"
        assert decision.model == "claude-opus-4.6"

    def test_difficulty_zero_matches_tier_without_max_difficulty(self) -> None:
        """difficulty=0 still matches tiers that have no max_difficulty.

        Tiers without a difficulty constraint are unaffected by
        unknown difficulty — they match based on their other
        constraints (tokens, messages, patterns).
        """
        from agentguard.proxy.routing.config import ModelTier, RoutingConfig
        from agentguard.proxy.routing.router import Router

        config = RoutingConfig(
            enabled=True,
            tiers=[
                ModelTier(
                    name="fast",
                    model="claude-sonnet-4",
                    max_tokens=10000,
                    # No max_difficulty — not dependent on classifier
                ),
                ModelTier(name="premium", model="claude-opus-4.6"),
            ],
            default_tier="premium",
        )
        router = Router(config)

        # difficulty=0 — fast tier has no max_difficulty constraint,
        # so it matches based on tokens alone
        decision = router.route(
            token_estimate=5000,
            message_count=5,
            content="",
            difficulty=0,
        )
        assert decision.tier_name == "fast"
        assert decision.model == "claude-sonnet-4"

    def test_difficulty_combined_with_tokens(self) -> None:
        """Difficulty constraint works alongside token constraint (AND logic)."""
        from agentguard.proxy.routing.config import ModelTier, RoutingConfig
        from agentguard.proxy.routing.router import Router

        config = RoutingConfig(
            enabled=True,
            tiers=[
                ModelTier(
                    name="fast",
                    model="claude-sonnet-4",
                    max_tokens=10000,
                    max_difficulty=1,
                ),
                ModelTier(name="premium", model="claude-opus-4"),
            ],
            default_tier="premium",
        )
        router = Router(config)

        # Both under threshold — matches fast
        decision = router.route(
            token_estimate=5000,
            message_count=5,
            content="",
            difficulty=1,
        )
        assert decision.tier_name == "fast"

        # Tokens under, difficulty over — falls through
        decision = router.route(
            token_estimate=5000,
            message_count=5,
            content="",
            difficulty=3,
        )
        assert decision.tier_name == "premium"

        # Tokens over, difficulty under — falls through
        decision = router.route(
            token_estimate=15000,
            message_count=5,
            content="",
            difficulty=1,
        )
        assert decision.tier_name == "premium"

    def test_difficulty_default_is_zero(self) -> None:
        """Calling route() without difficulty defaults to 0.

        When difficulty defaults to 0, tiers with max_difficulty are
        rejected (fail-closed on difficulty), so the request falls
        through to the next tier without a difficulty constraint.
        """
        from agentguard.proxy.routing.config import ModelTier, RoutingConfig
        from agentguard.proxy.routing.router import Router

        config = RoutingConfig(
            enabled=True,
            tiers=[
                ModelTier(
                    name="fast",
                    model="claude-sonnet-4",
                    max_difficulty=1,
                ),
                ModelTier(name="premium", model="claude-opus-4"),
            ],
            default_tier="premium",
        )
        router = Router(config)

        # No difficulty argument — defaults to 0, tier with
        # max_difficulty is rejected, falls through to premium
        decision = router.route(
            token_estimate=1000,
            message_count=5,
            content="",
        )
        assert decision.tier_name == "premium"

    def test_three_tier_difficulty_routing(self) -> None:
        """Three-tier setup: simple→fast, medium→standard, complex→premium."""
        from agentguard.proxy.routing.config import ModelTier, RoutingConfig
        from agentguard.proxy.routing.router import Router

        config = RoutingConfig(
            enabled=True,
            tiers=[
                ModelTier(
                    name="fast",
                    model="gpt-4o-mini",
                    max_difficulty=1,
                ),
                ModelTier(
                    name="standard",
                    model="claude-sonnet-4",
                    max_difficulty=2,
                ),
                ModelTier(name="premium", model="claude-opus-4"),
            ],
            default_tier="premium",
        )
        router = Router(config)

        # Simple → fast
        d = router.route(
            token_estimate=1000,
            message_count=5,
            content="",
            difficulty=1,
        )
        assert d.tier_name == "fast"

        # Medium → standard
        d = router.route(
            token_estimate=1000,
            message_count=5,
            content="",
            difficulty=2,
        )
        assert d.tier_name == "standard"

        # Complex → premium (no max_difficulty = unconditional match)
        d = router.route(
            token_estimate=1000,
            message_count=5,
            content="",
            difficulty=3,
        )
        assert d.tier_name == "premium"


class TestRouterDuplicateTierNames:
    """Tests for Router duplicate tier name detection (#265)."""

    def test_duplicate_tier_names_raises_value_error(self) -> None:
        """Router raises ValueError when tiers have duplicate names."""
        from agentguard.proxy.routing.config import ModelTier, RoutingConfig
        from agentguard.proxy.routing.router import Router

        config = RoutingConfig(
            enabled=True,
            tiers=[
                ModelTier(name="fast", model="claude-sonnet-4", max_tokens=5000),
                ModelTier(name="fast", model="claude-opus-4", max_tokens=10000),
            ],
            default_tier="fast",
        )

        with pytest.raises(ValueError, match="Duplicate tier name"):
            Router(config)

    def test_unique_tier_names_accepted(self) -> None:
        """Router accepts configs with unique tier names."""
        from agentguard.proxy.routing.config import ModelTier, RoutingConfig
        from agentguard.proxy.routing.router import Router

        config = RoutingConfig(
            enabled=True,
            tiers=[
                ModelTier(name="fast", model="claude-sonnet-4", max_tokens=5000),
                ModelTier(name="premium", model="claude-opus-4"),
            ],
            default_tier="premium",
        )

        # Should not raise
        router = Router(config)
        assert router is not None

    def test_three_tiers_with_duplicate_raises(self) -> None:
        """Three tiers with one duplicate pair raises ValueError."""
        from agentguard.proxy.routing.config import ModelTier, RoutingConfig
        from agentguard.proxy.routing.router import Router

        config = RoutingConfig(
            enabled=True,
            tiers=[
                ModelTier(name="fast", model="model-a"),
                ModelTier(name="standard", model="model-b"),
                ModelTier(name="fast", model="model-c"),
            ],
            default_tier="standard",
        )

        with pytest.raises(ValueError, match=r"Duplicate tier name.*fast"):
            Router(config)
