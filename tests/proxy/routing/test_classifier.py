"""Tests for the DifficultyClassifier HTTP client."""

from __future__ import annotations

import pytest


class TestDifficultyClassifier:
    """Tests for DifficultyClassifier.classify() HTTP client."""

    @pytest.mark.asyncio
    async def test_returns_1_for_simple(self) -> None:
        """Simple label maps to difficulty 1."""
        from unittest.mock import AsyncMock, MagicMock, patch

        from agentguard.proxy.routing.classifier import DifficultyClassifier

        classifier = DifficultyClassifier(
            url="http://localhost:11435",
            timeout=5.0,
        )

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.raise_for_status = MagicMock()
        mock_response.json.return_value = {
            "label": "Simple",
            "scores": {"Simple": 0.85, "Medium": 0.10, "Complex": 0.05},
            "model": "test",
        }

        mock_client = AsyncMock()
        mock_client.post.return_value = mock_response
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("httpx.AsyncClient", return_value=mock_client):
            result = await classifier.classify("What is 2+2?")

        assert result == 1

    @pytest.mark.asyncio
    async def test_returns_2_for_medium(self) -> None:
        """Medium label maps to difficulty 2."""
        from unittest.mock import AsyncMock, MagicMock, patch

        from agentguard.proxy.routing.classifier import DifficultyClassifier

        classifier = DifficultyClassifier(
            url="http://localhost:11435",
            timeout=5.0,
        )

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.raise_for_status = MagicMock()
        mock_response.json.return_value = {
            "label": "Medium",
            "scores": {"Simple": 0.10, "Medium": 0.80, "Complex": 0.10},
            "model": "test",
        }

        mock_client = AsyncMock()
        mock_client.post.return_value = mock_response
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("httpx.AsyncClient", return_value=mock_client):
            result = await classifier.classify("Explain how Python decorators work")

        assert result == 2

    @pytest.mark.asyncio
    async def test_returns_3_for_complex(self) -> None:
        """Complex label maps to difficulty 3."""
        from unittest.mock import AsyncMock, MagicMock, patch

        from agentguard.proxy.routing.classifier import DifficultyClassifier

        classifier = DifficultyClassifier(
            url="http://localhost:11435",
            timeout=5.0,
        )

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.raise_for_status = MagicMock()
        mock_response.json.return_value = {
            "label": "Complex",
            "scores": {"Simple": 0.02, "Medium": 0.03, "Complex": 0.95},
            "model": "test",
        }

        mock_client = AsyncMock()
        mock_client.post.return_value = mock_response
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("httpx.AsyncClient", return_value=mock_client):
            result = await classifier.classify(
                "Design a distributed consensus algorithm"
            )

        assert result == 3

    @pytest.mark.asyncio
    async def test_timeout_returns_0(self) -> None:
        """Timeout returns 0 (fail-open)."""
        from unittest.mock import AsyncMock, patch

        import httpx

        from agentguard.proxy.routing.classifier import DifficultyClassifier

        classifier = DifficultyClassifier(
            url="http://localhost:11435",
            timeout=0.1,
        )

        mock_client = AsyncMock()
        mock_client.post.side_effect = httpx.TimeoutException("timed out")
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("httpx.AsyncClient", return_value=mock_client):
            result = await classifier.classify("test query")

        assert result == 0

    @pytest.mark.asyncio
    async def test_http_error_returns_0(self) -> None:
        """HTTP error returns 0 (fail-open)."""
        from unittest.mock import AsyncMock, MagicMock, patch

        import httpx

        from agentguard.proxy.routing.classifier import DifficultyClassifier

        classifier = DifficultyClassifier(
            url="http://localhost:11435",
            timeout=5.0,
        )

        mock_response = MagicMock()
        mock_response.status_code = 503
        mock_response.raise_for_status.side_effect = httpx.HTTPStatusError(
            "Service Unavailable",
            request=MagicMock(),
            response=mock_response,
        )

        mock_client = AsyncMock()
        mock_client.post.return_value = mock_response
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("httpx.AsyncClient", return_value=mock_client):
            result = await classifier.classify("test query")

        assert result == 0

    @pytest.mark.asyncio
    async def test_malformed_response_returns_0(self) -> None:
        """Malformed JSON response returns 0 (fail-open)."""
        from unittest.mock import AsyncMock, MagicMock, patch

        from agentguard.proxy.routing.classifier import DifficultyClassifier

        classifier = DifficultyClassifier(
            url="http://localhost:11435",
            timeout=5.0,
        )

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.raise_for_status = MagicMock()
        mock_response.json.return_value = {"unexpected": "format"}

        mock_client = AsyncMock()
        mock_client.post.return_value = mock_response
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("httpx.AsyncClient", return_value=mock_client):
            result = await classifier.classify("test query")

        assert result == 0

    @pytest.mark.asyncio
    async def test_unknown_label_returns_0(self) -> None:
        """Unknown label returns 0 (fail-open)."""
        from unittest.mock import AsyncMock, MagicMock, patch

        from agentguard.proxy.routing.classifier import DifficultyClassifier

        classifier = DifficultyClassifier(
            url="http://localhost:11435",
            timeout=5.0,
        )

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.raise_for_status = MagicMock()
        mock_response.json.return_value = {
            "label": "Unknown",
            "scores": {},
            "model": "test",
        }

        mock_client = AsyncMock()
        mock_client.post.return_value = mock_response
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("httpx.AsyncClient", return_value=mock_client):
            result = await classifier.classify("test query")

        assert result == 0

    @pytest.mark.asyncio
    async def test_truncates_long_content(self) -> None:
        """Content is truncated to 2000 chars before sending."""
        from unittest.mock import AsyncMock, MagicMock, patch

        from agentguard.proxy.routing.classifier import DifficultyClassifier

        classifier = DifficultyClassifier(
            url="http://localhost:11435",
            timeout=5.0,
        )

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.raise_for_status = MagicMock()
        mock_response.json.return_value = {
            "label": "Simple",
            "scores": {"Simple": 0.85, "Medium": 0.10, "Complex": 0.05},
            "model": "test",
        }

        mock_client = AsyncMock()
        mock_client.post.return_value = mock_response
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        long_content = "x" * 10000

        with patch("httpx.AsyncClient", return_value=mock_client):
            await classifier.classify(long_content)

        # Verify the text was truncated in the request
        call_args = mock_client.post.call_args
        sent_text = call_args.kwargs.get("json", {}).get("text", "")
        assert len(sent_text) <= 2000

    def test_url_stripping(self) -> None:
        """Trailing slash is stripped from URL."""
        from agentguard.proxy.routing.classifier import DifficultyClassifier

        classifier = DifficultyClassifier(
            url="http://localhost:11435/",
            timeout=5.0,
        )
        assert classifier._url == "http://localhost:11435"
