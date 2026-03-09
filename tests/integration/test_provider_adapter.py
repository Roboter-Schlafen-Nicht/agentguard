"""SG-5: Provider Adapter Detection and Extraction.

Integration tests for provider detection, request/response
extraction, and equivalence with the legacy scanner module.
"""

from __future__ import annotations

import json

import pytest

from agentguard.proxy.providers import detect_provider, get_provider
from agentguard.proxy.providers.openai import OpenAIProvider
from agentguard.proxy.scanner import (
    extract_request_params,
    extract_response_params,
)

pytestmark = pytest.mark.integration


# ===========================================================================
# SG-5.1: detect_provider returns correct adapter
# ===========================================================================


class TestDetectProvider:
    """SG-5.1: Provider detection and lookup."""

    def test_detect_openai_provider(self) -> None:
        """detect_provider(provider_name='openai') returns OpenAIProvider."""
        provider = detect_provider(provider_name="openai")
        assert isinstance(provider, OpenAIProvider)
        assert provider.name == "openai"

    def test_detect_unknown_provider_raises(self) -> None:
        """detect_provider with unknown name raises ValueError."""
        with pytest.raises(ValueError, match="No provider named"):
            get_provider("nonexistent")

    def test_detect_default_provider(self) -> None:
        """detect_provider with no name returns OpenAI (default)."""
        provider = detect_provider(provider_name=None)
        assert isinstance(provider, OpenAIProvider)


# ===========================================================================
# SG-5.2: OpenAI provider vs legacy scanner extraction equivalence
# ===========================================================================


class TestExtractionEquivalence:
    """SG-5.2: Provider and legacy scanner produce same results."""

    def test_request_extraction_equivalence(self) -> None:
        """OpenAIProvider and scanner extract same request params."""
        body = json.dumps(
            {
                "model": "gpt-4",
                "messages": [
                    {"role": "system", "content": "You are helpful."},
                    {"role": "user", "content": "Hello there."},
                    {"role": "assistant", "content": "Hi!"},
                ],
                "temperature": 0.7,
            }
        ).encode()

        provider = OpenAIProvider()
        provider_params = provider.extract_request_params(body)
        scanner_params = extract_request_params(body)

        # Both should extract the same model
        assert provider_params.get("model") == scanner_params.get("model")
        # Both should extract messages content
        assert "messages" in provider_params
        assert "messages" in scanner_params
        assert provider_params["messages"] == scanner_params["messages"]
        # Both should extract system
        assert provider_params.get("system") == scanner_params.get("system")
        # Both should extract content (non-system messages)
        assert provider_params.get("content") == scanner_params.get("content")

    def test_response_extraction_equivalence(self) -> None:
        """OpenAIProvider and scanner extract same response params."""
        body = json.dumps(
            {
                "choices": [
                    {
                        "index": 0,
                        "message": {
                            "role": "assistant",
                            "content": "The answer is 42.",
                        },
                    }
                ]
            }
        ).encode()

        provider = OpenAIProvider()
        provider_params = provider.extract_response_params(body)
        scanner_params = extract_response_params(body)

        assert provider_params.get("content") == scanner_params.get("content")
        assert provider_params["content"] == "The answer is 42."


# ===========================================================================
# SG-5.3: Provider used in middleware when configured
# ===========================================================================


class TestProviderInMiddleware:
    """SG-5.3: Provider path is taken when configured in ProxyConfig."""

    def test_provider_configured_in_middleware(self) -> None:
        """Middleware uses provider when config.provider is set."""
        from unittest.mock import AsyncMock, patch

        import httpx
        from starlette.testclient import TestClient

        from agentguard.proxy.app import create_app
        from agentguard.proxy.config import ProxyConfig

        config = ProxyConfig(
            upstream_base_url="https://api.example.com",
            provider="openai",
        )
        app = create_app(config)
        client = TestClient(app, raise_server_exceptions=False)

        mock_resp = httpx.Response(
            200,
            json={"choices": [{"message": {"content": "Hello!"}, "index": 0}]},
        )

        with patch.object(
            app.state.middleware,
            "_forward_request",
            new_callable=AsyncMock,
            return_value=mock_resp,
        ):
            response = client.post(
                "/v1/chat/completions",
                json={
                    "model": "gpt-4",
                    "messages": [{"role": "user", "content": "Hi"}],
                },
            )

        assert response.status_code == 200
        # Verify provider was configured
        assert app.state.middleware.provider is not None
        assert app.state.middleware.provider.name == "openai"
