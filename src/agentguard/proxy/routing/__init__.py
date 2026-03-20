"""Model routing module for dynamic model selection.

Provides automatic model selection based on request complexity,
routing simple requests to fast/cheap models and complex requests
to premium models.
"""

from agentguard.proxy.routing.config import (
    ModelTier,
    RoutingConfig,
    configure_routing_logging,
    load_routing_config,
)
from agentguard.proxy.routing.router import Router, RoutingDecision

__all__ = [
    "ModelTier",
    "Router",
    "RoutingConfig",
    "RoutingDecision",
    "configure_routing_logging",
    "load_routing_config",
]
