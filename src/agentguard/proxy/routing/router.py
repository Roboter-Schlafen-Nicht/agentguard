"""Router for dynamic model selection based on request complexity.

Evaluates request metadata (token count, message count, content
patterns) against configured model tiers and returns a routing
decision specifying which model and upstream to use.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from agentguard.proxy.routing.config import RoutingConfig

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class RoutingDecision:
    """Result of routing a request to a model tier.

    Attributes:
        tier_name: Name of the matched tier (or "passthrough" if
            routing is disabled).
        model: Model name to use, or None if the original model
            should be preserved (passthrough).
        upstream_url: Override upstream URL, or None to use the
            default upstream.
        reason: Human-readable explanation of why this tier was chosen.
    """

    tier_name: str
    model: str | None
    upstream_url: str | None
    reason: str


class Router:
    """Route requests to model tiers based on complexity metrics.

    Evaluates tiers in order; the first matching tier wins.
    A tier matches when ALL of its constraints are satisfied:

    - ``max_tokens``: token estimate must be ≤ this value (if set)
    - ``max_messages``: message count must be ≤ this value (if set)
    - ``patterns``: at least one pattern must match the content
      (if non-empty; patterns are case-insensitive regexes)

    A tier with no constraints (no max_tokens, no max_messages, no
    patterns) matches unconditionally — use this as a catch-all at
    the end of the tier list.

    Args:
        config: Routing configuration with tiers.
    """

    def __init__(self, config: RoutingConfig) -> None:
        self._config = config
        # Pre-compile patterns for each tier
        self._compiled_patterns: dict[str, list[re.Pattern[str]]] = {}
        for tier in config.tiers:
            if tier.patterns:
                self._compiled_patterns[tier.name] = [
                    re.compile(p, re.IGNORECASE) for p in tier.patterns
                ]

    def route(
        self,
        token_estimate: int,
        message_count: int,
        content: str,
        difficulty: int = 0,
    ) -> RoutingDecision:
        """Route a request to a model tier.

        Args:
            token_estimate: Estimated token count of the request.
            message_count: Number of messages in the conversation.
            content: Concatenated text content of the request
                (used for pattern matching).
            difficulty: Difficulty level from the classifier (1-3),
                or 0 if unknown/unavailable.  0 skips difficulty
                constraints.

        Returns:
            A RoutingDecision specifying the tier, model, and
            optional upstream URL override.
        """
        if not self._config.enabled:
            logger.debug(
                "routing_disabled tokens=%d messages=%d",
                token_estimate,
                message_count,
            )
            return RoutingDecision(
                tier_name="passthrough",
                model=None,
                upstream_url=None,
                reason="Routing disabled",
            )

        # Evaluate tiers in order
        for tier in self._config.tiers:
            matched, reason = self._evaluate_tier(
                tier.name,
                token_estimate,
                message_count,
                content,
                difficulty,
            )
            if matched:
                decision = RoutingDecision(
                    tier_name=tier.name,
                    model=tier.model,
                    upstream_url=tier.upstream_url,
                    reason=reason,
                )
                logger.info(
                    "routing_decision tier=%s model=%s reason=%s"
                    " tokens=%d messages=%d difficulty=%d",
                    tier.name,
                    tier.model,
                    reason,
                    token_estimate,
                    message_count,
                    difficulty,
                )
                return decision

        # No tier matched — fall back to default
        return self._resolve_default(token_estimate, message_count, difficulty)

    def _evaluate_tier(
        self,
        tier_name: str,
        token_estimate: int,
        message_count: int,
        content: str,
        difficulty: int = 0,
    ) -> tuple[bool, str]:
        """Evaluate whether a request matches a specific tier.

        All constraints on the tier must be satisfied for a match.
        A tier with no constraints matches unconditionally.

        Args:
            tier_name: Name of the tier to evaluate.
            token_estimate: Estimated token count.
            message_count: Number of messages.
            content: Concatenated text content.
            difficulty: Difficulty level (1-3) or 0 to skip.

        Returns:
            Tuple of (matched, reason_string).
        """
        tier = next(t for t in self._config.tiers if t.name == tier_name)
        reasons: list[str] = []

        # Check token constraint
        if tier.max_tokens is not None:
            if token_estimate > tier.max_tokens:
                return False, ""
            reasons.append(f"tokens({token_estimate}) <= {tier.max_tokens}")

        # Check message constraint
        if tier.max_messages is not None:
            if message_count > tier.max_messages:
                return False, ""
            reasons.append(f"messages({message_count}) <= {tier.max_messages}")

        # Check difficulty constraint
        # When difficulty=0 (unknown / classifier failure) and the
        # tier has a max_difficulty constraint, the tier is REJECTED.
        # This is fail-closed on the difficulty dimension: we route
        # to the more capable (and expensive) model rather than risk
        # sending a complex request to a cheap model.
        if tier.max_difficulty is not None:
            if difficulty == 0:
                return False, ""
            if difficulty > tier.max_difficulty:
                return False, ""
            reasons.append(f"difficulty({difficulty}) <= {tier.max_difficulty}")

        # Check pattern constraint
        compiled = self._compiled_patterns.get(tier_name, [])
        if compiled:
            pattern_matched = any(p.search(content) for p in compiled)
            if not pattern_matched:
                return False, ""
            reasons.append("pattern matched")

        # All constraints passed (or tier has no constraints)
        if not reasons:
            reasons.append("unconditional match")

        return True, "; ".join(reasons)

    def _resolve_default(
        self,
        token_estimate: int,
        message_count: int,
        difficulty: int = 0,
    ) -> RoutingDecision:
        """Resolve the default tier when no tiers matched.

        Looks up the tier named by ``default_tier`` in the config.
        If not found, uses the last tier in the list.

        Returns:
            A RoutingDecision for the default/fallback tier.
        """
        default_name = self._config.default_tier

        # Find the default tier by name
        for tier in self._config.tiers:
            if tier.name == default_name:
                logger.info(
                    "routing_default tier=%s model=%s"
                    " tokens=%d messages=%d difficulty=%d",
                    tier.name,
                    tier.model,
                    token_estimate,
                    message_count,
                    difficulty,
                )
                return RoutingDecision(
                    tier_name=tier.name,
                    model=tier.model,
                    upstream_url=tier.upstream_url,
                    reason=f"Default tier '{default_name}'",
                )

        # Default tier name not found — use last tier as fallback
        if self._config.tiers:
            last = self._config.tiers[-1]
            logger.warning(
                "routing_default_not_found default_tier=%s "
                "fallback_tier=%s tokens=%d messages=%d difficulty=%d",
                default_name,
                last.name,
                token_estimate,
                message_count,
                difficulty,
            )
            return RoutingDecision(
                tier_name=last.name,
                model=last.model,
                upstream_url=last.upstream_url,
                reason=f"Default tier '{default_name}' not found; using last tier",
            )

        # No tiers at all — passthrough
        logger.warning(
            "routing_no_tiers default_tier=%s tokens=%d messages=%d difficulty=%d",
            default_name,
            token_estimate,
            message_count,
            difficulty,
        )
        return RoutingDecision(
            tier_name="passthrough",
            model=None,
            upstream_url=None,
            reason="No tiers configured",
        )
