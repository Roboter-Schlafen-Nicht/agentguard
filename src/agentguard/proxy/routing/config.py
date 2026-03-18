"""Configuration dataclasses for model routing.

Defines ModelTier and RoutingConfig for specifying how requests
are routed to different models based on complexity metrics.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    pass


@dataclass
class ModelTier:
    """A model tier defines routing rules for a specific model.

    Attributes:
        name: Unique identifier for this tier (e.g., "fast", "premium").
        model: Model name to use when this tier matches
            (e.g., "claude-sonnet-4", "claude-opus-4").
        upstream_url: Optional override for the upstream API URL.
            If set, requests matching this tier are sent to this URL
            instead of the default upstream.
        max_tokens: Maximum token estimate for this tier. If set,
            requests with token estimates above this value do not
            match this tier.
        max_messages: Maximum message count for this tier. If set,
            requests with more messages do not match this tier.
        patterns: List of regex patterns. If non-empty, at least one
            pattern must match the request content for this tier to
            match. Patterns are matched case-insensitively.
    """

    name: str
    model: str
    upstream_url: str | None = None
    max_tokens: int | None = None
    max_messages: int | None = None
    patterns: list[str] = field(default_factory=list)


@dataclass
class RoutingConfig:
    """Configuration for model routing.

    Attributes:
        enabled: Whether routing is enabled. If False, all requests
            pass through without model changes.
        tiers: Ordered list of model tiers. Tiers are evaluated in
            order; the first matching tier is used.
        default_tier: Name of the tier to use when no tiers match.
            Should match a tier name in the tiers list.
    """

    enabled: bool = False
    tiers: list[ModelTier] = field(default_factory=list)
    default_tier: str = "default"


def load_routing_config(path: Path | str) -> RoutingConfig:
    """Load a RoutingConfig from a YAML file.

    Args:
        path: Path to the YAML configuration file.

    Returns:
        A RoutingConfig instance.

    Raises:
        ValueError: If the YAML is invalid or missing required fields.
        FileNotFoundError: If the file does not exist.
    """
    import yaml

    path = Path(path)
    if not path.is_file():
        msg = f"Routing config file not found: {path}"
        raise FileNotFoundError(msg)

    raw = path.read_text(encoding="utf-8")
    try:
        data = yaml.safe_load(raw)
    except yaml.YAMLError as exc:
        msg = f"Invalid YAML in routing config: {exc}"
        raise ValueError(msg) from exc

    if not isinstance(data, dict):
        msg = f"Invalid routing config: expected object, got {type(data).__name__}"
        raise ValueError(msg)

    return _parse_routing_config(data)


def _parse_routing_config(data: dict[str, Any]) -> RoutingConfig:
    """Parse a RoutingConfig from a dictionary.

    Args:
        data: Dictionary parsed from YAML.

    Returns:
        A RoutingConfig instance.

    Raises:
        ValueError: If required fields are missing or invalid.
    """
    enabled = data.get("enabled", False)
    default_tier = data.get("default_tier", "default")

    tiers_data = data.get("tiers")
    if tiers_data is None:
        msg = "Routing config missing 'tiers' field"
        raise ValueError(msg)

    if not isinstance(tiers_data, list):
        msg = f"'tiers' must be a list, got {type(tiers_data).__name__}"
        raise ValueError(msg)

    tiers: list[ModelTier] = []
    for i, tier_data in enumerate(tiers_data):
        if not isinstance(tier_data, dict):
            msg = f"Tier {i} must be an object, got {type(tier_data).__name__}"
            raise ValueError(msg)
        tiers.append(_parse_model_tier(tier_data, i))

    return RoutingConfig(
        enabled=bool(enabled),
        tiers=tiers,
        default_tier=str(default_tier),
    )


def _parse_model_tier(data: dict[str, Any], index: int) -> ModelTier:
    """Parse a ModelTier from a dictionary.

    Args:
        data: Dictionary parsed from YAML.
        index: Tier index for error messages.

    Returns:
        A ModelTier instance.

    Raises:
        ValueError: If required fields are missing.
    """
    name = data.get("name")
    if name is None:
        msg = f"Tier {index} missing 'name' field"
        raise ValueError(msg)

    model = data.get("model")
    if model is None:
        msg = f"Tier {index} ('{name}') missing 'model' field"
        raise ValueError(msg)

    patterns = data.get("patterns", [])
    if not isinstance(patterns, list):
        patterns = [patterns]

    return ModelTier(
        name=str(name),
        model=str(model),
        upstream_url=data.get("upstream_url"),
        max_tokens=data.get("max_tokens"),
        max_messages=data.get("max_messages"),
        patterns=[str(p) for p in patterns],
    )
