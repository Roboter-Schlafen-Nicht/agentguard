"""LLM API provider adapters.

Defines the Provider protocol and a registry for looking up providers
by name.  Each provider knows how to parse request and response bodies
for a specific LLM API format (e.g. OpenAI, Anthropic).

Public API:
- ``Provider`` — runtime-checkable protocol for provider adapters.
- ``get_provider(name)`` — look up a provider by name.
- ``list_providers()`` — list all registered provider names.
- ``detect_provider(...)`` — auto-detect the provider to use.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable


@runtime_checkable
class Provider(Protocol):
    """Protocol for LLM API format adapters.

    Each provider implements request/response parsing and streaming
    content extraction for a specific LLM API format.

    Attributes:
        name: Short identifier for this provider (e.g. ``"openai"``).
    """

    @property
    def name(self) -> str:
        """Short identifier for this provider."""
        ...

    def extract_request_params(
        self, body: bytes, *, seen_count: int | None = None
    ) -> dict[str, str]:
        """Extract scannable parameters from a request body.

        Args:
            body: Raw request body bytes.
            seen_count: Number of messages already scanned.  When
                provided, only messages at index ``seen_count:`` are
                extracted (delta scanning).

        Returns:
            Dictionary mapping parameter keys (``messages``, ``system``,
            ``content``, ``model``) to string values for policy scanning.

        Raises:
            ValueError: If the body is not valid JSON.
        """
        ...

    def extract_response_params(self, body: bytes) -> dict[str, str]:
        """Extract scannable parameters from a response body.

        Args:
            body: Raw response body bytes.

        Returns:
            Dictionary mapping parameter keys (``content``) to string
            values for policy scanning.

        Raises:
            ValueError: If the body is not valid JSON.
        """
        ...

    def extract_stream_content(self, data_str: str) -> list[str]:
        """Extract content strings from a streaming SSE data payload.

        Args:
            data_str: The JSON string after the ``data: `` prefix.

        Returns:
            List of content strings found in the payload (may be empty).
        """
        ...


def _build_registry() -> dict[str, Provider]:
    """Build the provider registry lazily."""
    from agentguard.proxy.providers.openai import OpenAIProvider

    return {
        "openai": OpenAIProvider(),
    }


_registry: dict[str, Provider] | None = None


def _get_registry() -> dict[str, Provider]:
    """Get or create the provider registry."""
    global _registry
    if _registry is None:
        _registry = _build_registry()
    return _registry


def list_providers() -> list[str]:
    """List all registered provider names.

    Returns:
        Sorted list of provider names.
    """
    return sorted(_get_registry().keys())


def get_provider(name: str) -> Provider:
    """Look up a provider by name.

    Args:
        name: The provider name (e.g. ``"openai"``).

    Returns:
        The provider instance.

    Raises:
        ValueError: If no provider with that name is registered.
    """
    registry = _get_registry()
    if name not in registry:
        available = ", ".join(sorted(registry.keys()))
        msg = f"No provider named '{name}'. Available: {available}"
        raise ValueError(msg)
    return registry[name]


def detect_provider(
    *,
    provider_name: str | None = None,
) -> Provider:
    """Detect or look up the appropriate provider.

    If ``provider_name`` is given, looks it up directly.  Otherwise
    returns the default provider (OpenAI-compatible, since most LLM
    APIs support OpenAI format).

    Args:
        provider_name: Explicit provider name, or None for default.

    Returns:
        The detected/selected provider instance.

    Raises:
        ValueError: If the named provider is not registered.
    """
    if provider_name is not None:
        return get_provider(provider_name)
    # Default: OpenAI format (covers OpenAI, Azure, Copilot, vLLM, etc.)
    return get_provider("openai")
