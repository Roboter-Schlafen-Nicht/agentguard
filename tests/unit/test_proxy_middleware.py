"""Tests for the GuardMiddleware."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from agentguard.proxy.config import ProxyConfig
from agentguard.proxy.middleware import GuardMiddleware, _StreamContext

if TYPE_CHECKING:
    from pathlib import Path

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def base_config() -> ProxyConfig:
    """Create a minimal ProxyConfig for testing."""
    return ProxyConfig(upstream_base_url="https://api.openai.com")


@pytest.fixture
def policy_dir(tmp_path: Path) -> Path:
    """Create a temp directory with an LLM request policy."""
    d = tmp_path / "policies"
    d.mkdir()
    policy = d / "no-secrets-in-prompt.yaml"
    policy.write_text(
        "name: no-secrets-in-prompt\n"
        "description: Block secrets in LLM requests\n"
        "rules:\n"
        "  - action: llm_request\n"
        "    deny:\n"
        "      - pattern: 'password\\s*[:=]'\n"
        "      - pattern: 'api[_-]?key\\s*[:=]'\n"
        "    severity: critical\n"
        "    scan: messages\n"
    )
    return d


@pytest.fixture
def response_policy_dir(tmp_path: Path) -> Path:
    """Create a temp directory with an LLM response policy."""
    d = tmp_path / "policies"
    d.mkdir()
    policy = d / "no-harmful-output.yaml"
    policy.write_text(
        "name: no-harmful-output\n"
        "description: Block harmful content in responses\n"
        "rules:\n"
        "  - action: llm_response\n"
        "    deny:\n"
        "      - pattern: 'HARMFUL_CONTENT'\n"
        "    severity: high\n"
        "    scan: content\n"
    )
    return d


def _make_request(
    body: dict | None = None,
    path: str = "/v1/chat/completions",
    method: str = "POST",
    query: str = "",
) -> MagicMock:
    """Create a mock Starlette Request."""
    request = MagicMock()
    request.method = method
    request.url.path = path
    request.url.query = query
    raw_body = json.dumps(body).encode() if body else b""
    request.body = AsyncMock(return_value=raw_body)
    request.headers = {"content-type": "application/json", "host": "localhost:8080"}
    return request


def _openai_request_body(
    messages: list[dict] | None = None,
    model: str = "gpt-4",
    stream: bool = False,
) -> dict:
    """Build an OpenAI chat completion request body."""
    body: dict = {"model": model}
    if messages is not None:
        body["messages"] = messages
    else:
        body["messages"] = [{"role": "user", "content": "Hello"}]
    if stream:
        body["stream"] = True
    return body


# ===========================================================================
# Test: Middleware construction
# ===========================================================================


class TestGuardMiddlewareConstruction:
    """Test middleware initialization."""

    def test_creates_guard_with_no_policies(self, base_config: ProxyConfig) -> None:
        """Middleware with no policy_dir should create empty guard."""
        mw = GuardMiddleware(base_config)
        assert len(mw.guard.policies) == 0
        assert mw.session_id.startswith("proxy-")
        assert mw.audit_log.session_id == mw.session_id

    def test_creates_guard_with_policies(self, policy_dir: Path) -> None:
        """Middleware with policy_dir should load policies."""
        config = ProxyConfig(
            upstream_base_url="https://api.openai.com",
            policy_dir=str(policy_dir),
        )
        mw = GuardMiddleware(config)
        assert len(mw.guard.policies) == 1
        assert mw.guard.policies[0].name == "no-secrets-in-prompt"

    def test_raises_for_nonexistent_policy_dir(self, tmp_path: Path) -> None:
        """Nonexistent policy_dir should raise FileNotFoundError."""
        config = ProxyConfig(
            upstream_base_url="https://api.openai.com",
            policy_dir=str(tmp_path / "nonexistent"),
        )
        with pytest.raises(FileNotFoundError):
            GuardMiddleware(config)

    def test_loads_builtins(self) -> None:
        """load_builtins=True should load built-in policies."""
        config = ProxyConfig(
            upstream_base_url="https://api.openai.com",
            load_builtins=True,
        )
        mw = GuardMiddleware(config)
        assert len(mw.guard.policies) > 0

    def test_loads_auto_discover(self) -> None:
        """auto_discover=True should load auto-discovered policies."""
        config = ProxyConfig(
            upstream_base_url="https://api.openai.com",
            auto_discover=True,
        )
        mw = GuardMiddleware(config)
        # auto_discover may or may not find policies depending on env
        assert isinstance(mw.guard.policies, list)


# ===========================================================================
# Test: Request policy enforcement
# ===========================================================================


class TestRequestPolicyEnforcement:
    """Test that requests are checked against policies."""

    @pytest.mark.anyio
    async def test_allowed_request(self, base_config: ProxyConfig) -> None:
        """Request with no policies should be forwarded."""
        mw = GuardMiddleware(base_config)
        request = _make_request(body=_openai_request_body())

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.content = json.dumps(
            {"choices": [{"message": {"content": "Hi!"}}]}
        ).encode()
        mock_response.headers = {"content-type": "application/json"}

        with patch.object(mw, "_forward_request", return_value=mock_response):
            response = await mw.handle_request(request)

        assert response.status_code == 200

    @pytest.mark.anyio
    async def test_denied_request_returns_403(self, policy_dir: Path) -> None:
        """Request matching a deny policy should return 403."""
        config = ProxyConfig(
            upstream_base_url="https://api.openai.com",
            policy_dir=str(policy_dir),
        )
        mw = GuardMiddleware(config)
        request = _make_request(
            body=_openai_request_body(
                messages=[
                    {"role": "user", "content": "My password: hunter2"},
                ]
            )
        )

        response = await mw.handle_request(request)
        assert response.status_code == 403
        body = json.loads(response.body.decode())
        assert body["error"] == "request denied by policy"
        assert body["denied_by"] == "no-secrets-in-prompt"

    @pytest.mark.anyio
    async def test_denied_request_is_audited(
        self,
        policy_dir: Path,
        tmp_path: Path,
    ) -> None:
        """Denied request should be recorded in audit log."""
        audit_dir = tmp_path / "audit"
        audit_dir.mkdir()
        config = ProxyConfig(
            upstream_base_url="https://api.openai.com",
            policy_dir=str(policy_dir),
            audit_dir=str(audit_dir),
        )
        mw = GuardMiddleware(config)
        request = _make_request(
            body=_openai_request_body(
                messages=[
                    {"role": "user", "content": "api_key: sk-abc123"},
                ]
            )
        )

        await mw.handle_request(request)

        assert len(mw.audit_log.entries) == 1
        entry = mw.audit_log.entries[0]
        assert entry.action == "llm_request"
        assert entry.result == "denied"
        # Check audit was persisted
        jsonl_files = list(audit_dir.glob("*.jsonl"))
        assert len(jsonl_files) == 1

    @pytest.mark.anyio
    async def test_allowed_request_is_audited(self, base_config: ProxyConfig) -> None:
        """Allowed request should be recorded in audit log."""
        mw = GuardMiddleware(base_config)
        request = _make_request(body=_openai_request_body())

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.content = json.dumps({"choices": []}).encode()
        mock_response.headers = {"content-type": "application/json"}

        with patch.object(mw, "_forward_request", return_value=mock_response):
            await mw.handle_request(request)

        assert len(mw.audit_log.entries) == 1
        assert mw.audit_log.entries[0].result == "allowed"


# ===========================================================================
# Test: Endpoint filtering
# ===========================================================================


class TestEndpointFiltering:
    """Test allowed_endpoints configuration."""

    @pytest.mark.anyio
    async def test_disallowed_endpoint_returns_404(self) -> None:
        """Request to non-allowed endpoint should return 404."""
        config = ProxyConfig(
            upstream_base_url="https://api.openai.com",
            allowed_endpoints=["/v1/chat/completions"],
        )
        mw = GuardMiddleware(config)
        request = _make_request(
            body=_openai_request_body(),
            path="/v1/embeddings",
        )

        response = await mw.handle_request(request)
        assert response.status_code == 404

    @pytest.mark.anyio
    async def test_allowed_endpoint_passes(self) -> None:
        """Request to allowed endpoint should be processed."""
        config = ProxyConfig(
            upstream_base_url="https://api.openai.com",
            allowed_endpoints=["/v1/chat/completions"],
        )
        mw = GuardMiddleware(config)
        request = _make_request(
            body=_openai_request_body(),
            path="/v1/chat/completions",
        )

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.content = json.dumps({"choices": []}).encode()
        mock_response.headers = {"content-type": "application/json"}

        with patch.object(mw, "_forward_request", return_value=mock_response):
            response = await mw.handle_request(request)

        assert response.status_code == 200

    @pytest.mark.anyio
    async def test_empty_allowed_endpoints_passes_all(
        self, base_config: ProxyConfig
    ) -> None:
        """Empty allowed_endpoints should pass all paths."""
        mw = GuardMiddleware(base_config)
        request = _make_request(
            body=_openai_request_body(),
            path="/any/random/path",
        )

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.content = json.dumps({"choices": []}).encode()
        mock_response.headers = {"content-type": "application/json"}

        with patch.object(mw, "_forward_request", return_value=mock_response):
            response = await mw.handle_request(request)

        assert response.status_code == 200


# ===========================================================================
# Test: Response scanning
# ===========================================================================


class TestResponseScanning:
    """Test response scanning when scan_responses=True."""

    @pytest.mark.anyio
    async def test_response_scanning_disabled_by_default(
        self, response_policy_dir: Path
    ) -> None:
        """scan_responses=False should not scan responses."""
        config = ProxyConfig(
            upstream_base_url="https://api.openai.com",
            policy_dir=str(response_policy_dir),
            scan_responses=False,
        )
        mw = GuardMiddleware(config)
        request = _make_request(body=_openai_request_body())

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.content = json.dumps(
            {"choices": [{"message": {"content": "HARMFUL_CONTENT here"}}]}
        ).encode()
        mock_response.headers = {"content-type": "application/json"}

        with patch.object(mw, "_forward_request", return_value=mock_response):
            response = await mw.handle_request(request)

        # Should pass through even though response has harmful content
        assert response.status_code == 200

    @pytest.mark.anyio
    async def test_response_scanning_blocks_harmful_content(
        self, response_policy_dir: Path
    ) -> None:
        """scan_responses=True should block harmful response content."""
        config = ProxyConfig(
            upstream_base_url="https://api.openai.com",
            policy_dir=str(response_policy_dir),
            scan_responses=True,
        )
        mw = GuardMiddleware(config)
        request = _make_request(body=_openai_request_body())

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.content = json.dumps(
            {"choices": [{"message": {"content": "HARMFUL_CONTENT detected"}}]}
        ).encode()
        mock_response.headers = {"content-type": "application/json"}

        with patch.object(mw, "_forward_request", return_value=mock_response):
            response = await mw.handle_request(request)

        assert response.status_code == 403
        body = json.loads(response.body.decode())
        assert body["error"] == "response denied by policy"

    @pytest.mark.anyio
    async def test_response_scanning_allows_clean_content(
        self, response_policy_dir: Path
    ) -> None:
        """scan_responses=True should allow clean response content."""
        config = ProxyConfig(
            upstream_base_url="https://api.openai.com",
            policy_dir=str(response_policy_dir),
            scan_responses=True,
        )
        mw = GuardMiddleware(config)
        request = _make_request(body=_openai_request_body())

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.content = json.dumps(
            {"choices": [{"message": {"content": "This is perfectly safe."}}]}
        ).encode()
        mock_response.headers = {"content-type": "application/json"}

        with patch.object(mw, "_forward_request", return_value=mock_response):
            response = await mw.handle_request(request)

        assert response.status_code == 200


# ===========================================================================
# Test: Upstream error handling
# ===========================================================================


class TestUpstreamErrorHandling:
    """Test handling of upstream errors."""

    @pytest.mark.anyio
    async def test_upstream_error_returns_502(self, base_config: ProxyConfig) -> None:
        """Upstream connection error should return 502."""
        import httpx

        mw = GuardMiddleware(base_config)
        request = _make_request(body=_openai_request_body())

        with patch.object(
            mw,
            "_forward_request",
            side_effect=httpx.ConnectError("Connection refused"),
        ):
            response = await mw.handle_request(request)

        assert response.status_code == 502
        body = json.loads(response.body.decode())
        assert body["error"] == "upstream request failed"

    @pytest.mark.anyio
    async def test_upstream_error_is_audited(self, base_config: ProxyConfig) -> None:
        """Upstream errors should be recorded in audit log."""
        import httpx

        mw = GuardMiddleware(base_config)
        request = _make_request(body=_openai_request_body())

        with patch.object(
            mw,
            "_forward_request",
            side_effect=httpx.TimeoutException("Request timed out"),
        ):
            await mw.handle_request(request)

        assert len(mw.audit_log.entries) == 1
        assert mw.audit_log.entries[0].result == "error"


# ===========================================================================
# Test: Non-JSON passthrough
# ===========================================================================


class TestNonJsonPassthrough:
    """Test that non-JSON requests pass through without scanning."""

    @pytest.mark.anyio
    async def test_non_json_body_passes_through(self, base_config: ProxyConfig) -> None:
        """Non-JSON body should be forwarded without scanning."""
        mw = GuardMiddleware(base_config)
        request = MagicMock()
        request.method = "POST"
        request.url.path = "/v1/audio/transcriptions"
        request.url.query = ""
        request.body = AsyncMock(return_value=b"binary audio data")
        request.headers = {"content-type": "multipart/form-data", "host": "localhost"}

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.content = b'{"text": "transcription"}'
        mock_response.headers = {"content-type": "application/json"}

        with patch.object(mw, "_forward_request", return_value=mock_response):
            response = await mw.handle_request(request)

        assert response.status_code == 200


# ===========================================================================
# Test: Streaming detection
# ===========================================================================


class TestStreamingDetection:
    """Test streaming request detection."""

    def test_streaming_request_detected(self, base_config: ProxyConfig) -> None:
        """Request with stream=True should be detected."""
        mw = GuardMiddleware(base_config)
        body = json.dumps({"stream": True, "messages": []}).encode()
        assert mw._is_streaming_request(body) is True

    def test_non_streaming_request_detected(self, base_config: ProxyConfig) -> None:
        """Request without stream should not be detected as streaming."""
        mw = GuardMiddleware(base_config)
        body = json.dumps({"messages": []}).encode()
        assert mw._is_streaming_request(body) is False

    def test_stream_false_not_streaming(self, base_config: ProxyConfig) -> None:
        """Request with stream=False should not be streaming."""
        mw = GuardMiddleware(base_config)
        body = json.dumps({"stream": False, "messages": []}).encode()
        assert mw._is_streaming_request(body) is False

    def test_non_json_not_streaming(self, base_config: ProxyConfig) -> None:
        """Non-JSON body should not be streaming."""
        mw = GuardMiddleware(base_config)
        assert mw._is_streaming_request(b"not json") is False


# ===========================================================================
# Test: Header filtering
# ===========================================================================


class TestHeaderFiltering:
    """Test response header filtering."""

    def test_hop_by_hop_headers_removed(self, base_config: ProxyConfig) -> None:
        """Hop-by-hop headers should be filtered out."""
        mw = GuardMiddleware(base_config)
        headers = {
            "content-type": "application/json",
            "transfer-encoding": "chunked",
            "connection": "keep-alive",
            "x-request-id": "abc123",
        }
        filtered = mw._filter_response_headers(headers)
        assert "content-type" in filtered
        assert "x-request-id" in filtered
        assert "transfer-encoding" not in filtered
        assert "connection" not in filtered


# ===========================================================================
# Test: Query string forwarding
# ===========================================================================


class TestQueryStringForwarding:
    """Test that query strings are forwarded to upstream."""

    @pytest.mark.anyio
    async def test_query_string_forwarded(self, base_config: ProxyConfig) -> None:
        """Query string from client should be appended to upstream URL."""
        mw = GuardMiddleware(base_config)
        request = _make_request(
            body=_openai_request_body(),
            query="api-version=2024-01-01",
        )

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.content = json.dumps({"choices": []}).encode()
        mock_response.headers = {"content-type": "application/json"}

        with patch.object(
            mw, "_forward_request", return_value=mock_response
        ) as mock_fwd:
            await mw.handle_request(request)

        # Verify the upstream URL included the query string
        call_args = mock_fwd.call_args
        upstream_url = call_args[0][1]
        assert "?api-version=2024-01-01" in upstream_url


# ===========================================================================
# Test: Streaming request forwarding
# ===========================================================================


class TestStreamingRequestForwarding:
    """Test streaming request handling path."""

    @pytest.mark.anyio
    async def test_streaming_request_forwarded(self, base_config: ProxyConfig) -> None:
        """Streaming request returns a StreamingResponse."""
        mw = GuardMiddleware(base_config)
        request = _make_request(body=_openai_request_body(stream=True))

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.headers = {"content-type": "text/event-stream"}

        async def fake_aiter_bytes():
            yield b"data: {}\n\n"

        mock_response.aiter_bytes = fake_aiter_bytes

        mock_client = MagicMock()
        stream_ctx = _StreamContext(client=mock_client, response=mock_response)

        with patch.object(mw, "_forward_streaming", return_value=stream_ctx):
            response = await mw.handle_request(request)

        assert response.status_code == 200
        # StreamingResponse has media_type attribute
        assert "event-stream" in (response.media_type or "")

    @pytest.mark.anyio
    async def test_streaming_upstream_error_returns_502(
        self, base_config: ProxyConfig
    ) -> None:
        """Streaming upstream error should return 502."""
        import httpx

        mw = GuardMiddleware(base_config)
        request = _make_request(body=_openai_request_body(stream=True))

        with patch.object(
            mw,
            "_forward_streaming",
            side_effect=httpx.ConnectError("Connection refused"),
        ):
            response = await mw.handle_request(request)

        assert response.status_code == 502

    @pytest.mark.anyio
    async def test_streaming_response_has_background_cleanup(
        self, base_config: ProxyConfig
    ) -> None:
        """Streaming response should have a BackgroundTask for cleanup."""
        mw = GuardMiddleware(base_config)
        request = _make_request(body=_openai_request_body(stream=True))

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.headers = {"content-type": "text/event-stream"}

        async def fake_aiter_bytes():
            yield b"data: {}\n\n"

        mock_response.aiter_bytes = fake_aiter_bytes

        mock_client = MagicMock()
        stream_ctx = _StreamContext(client=mock_client, response=mock_response)

        with patch.object(mw, "_forward_streaming", return_value=stream_ctx):
            response = await mw.handle_request(request)

        # StreamingResponse should have background task attached
        assert response.background is not None

    @pytest.mark.anyio
    async def test_cleanup_stream_closes_response_and_client(self) -> None:
        """_cleanup_stream should close both response and client."""
        mock_client = AsyncMock()
        mock_response = AsyncMock()

        await GuardMiddleware._cleanup_stream(mock_client, mock_response)

        mock_response.aclose.assert_awaited_once()
        mock_client.aclose.assert_awaited_once()


# ===========================================================================
# Test: Response scanning edge cases
# ===========================================================================


class TestResponseScanningEdgeCases:
    """Test edge cases in response scanning."""

    @pytest.mark.anyio
    async def test_response_scanning_non_json_response_skipped(
        self, response_policy_dir: Path
    ) -> None:
        """Non-JSON response body with scan_responses=True should pass through."""
        config = ProxyConfig(
            upstream_base_url="https://api.openai.com",
            policy_dir=str(response_policy_dir),
            scan_responses=True,
        )
        mw = GuardMiddleware(config)
        request = _make_request(body=_openai_request_body())

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.content = b"not json at all"
        mock_response.headers = {"content-type": "text/plain"}

        with patch.object(mw, "_forward_request", return_value=mock_response):
            response = await mw.handle_request(request)

        # Should pass through since non-JSON can't be scanned
        assert response.status_code == 200

    @pytest.mark.anyio
    async def test_response_scanning_empty_body_skipped(
        self, response_policy_dir: Path
    ) -> None:
        """Empty response body with scan_responses=True should pass through."""
        config = ProxyConfig(
            upstream_base_url="https://api.openai.com",
            policy_dir=str(response_policy_dir),
            scan_responses=True,
        )
        mw = GuardMiddleware(config)
        request = _make_request(body=_openai_request_body())

        mock_response = MagicMock()
        mock_response.status_code = 204
        mock_response.content = b""
        mock_response.headers = {"content-type": "application/json"}

        with patch.object(mw, "_forward_request", return_value=mock_response):
            response = await mw.handle_request(request)

        assert response.status_code == 204

    @pytest.mark.anyio
    async def test_response_denied_is_audited(
        self,
        response_policy_dir: Path,
        tmp_path: Path,
    ) -> None:
        """Denied response should be recorded in audit log."""
        audit_dir = tmp_path / "audit"
        audit_dir.mkdir()
        config = ProxyConfig(
            upstream_base_url="https://api.openai.com",
            policy_dir=str(response_policy_dir),
            scan_responses=True,
            audit_dir=str(audit_dir),
        )
        mw = GuardMiddleware(config)
        request = _make_request(body=_openai_request_body())

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.content = json.dumps(
            {"choices": [{"message": {"content": "HARMFUL_CONTENT"}}]}
        ).encode()
        mock_response.headers = {"content-type": "application/json"}

        with patch.object(mw, "_forward_request", return_value=mock_response):
            response = await mw.handle_request(request)

        assert response.status_code == 403
        # Should have 2 audit entries: allowed request + denied response
        assert len(mw.audit_log.entries) == 2
        assert mw.audit_log.entries[0].result == "allowed"
        assert mw.audit_log.entries[1].result == "denied"
        assert mw.audit_log.entries[1].action == "llm_response"


# ===========================================================================
# Test: Audit metadata enrichment (message_count, token_estimate)
# ===========================================================================


class TestAuditMetadataEnrichment:
    """Test that audit entries include message_count and token_estimate."""

    @pytest.mark.anyio
    async def test_allowed_request_has_message_count(
        self, base_config: ProxyConfig
    ) -> None:
        """Allowed request audit should include message_count."""
        mw = GuardMiddleware(base_config)
        messages = [
            {"role": "system", "content": "You are helpful."},
            {"role": "user", "content": "Hello there!"},
        ]
        request = _make_request(body=_openai_request_body(messages=messages))

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.content = json.dumps({"choices": []}).encode()
        mock_response.headers = {"content-type": "application/json"}

        with patch.object(mw, "_forward_request", return_value=mock_response):
            await mw.handle_request(request)

        assert len(mw.audit_log.entries) == 1
        meta = mw.audit_log.entries[0].metadata
        assert "message_count" in meta
        assert meta["message_count"] == "2"

    @pytest.mark.anyio
    async def test_allowed_request_has_token_estimate(
        self, base_config: ProxyConfig
    ) -> None:
        """Allowed request audit should include token_estimate."""
        mw = GuardMiddleware(base_config)
        messages = [
            {"role": "user", "content": "Tell me about Python programming."},
        ]
        request = _make_request(body=_openai_request_body(messages=messages))

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.content = json.dumps({"choices": []}).encode()
        mock_response.headers = {"content-type": "application/json"}

        with patch.object(mw, "_forward_request", return_value=mock_response):
            await mw.handle_request(request)

        meta = mw.audit_log.entries[0].metadata
        assert "token_estimate" in meta
        # Token estimate should be a positive string-encoded integer
        assert int(meta["token_estimate"]) > 0

    @pytest.mark.anyio
    async def test_denied_request_has_message_count(self, policy_dir: Path) -> None:
        """Denied request audit should include message_count."""
        config = ProxyConfig(
            upstream_base_url="https://api.openai.com",
            policy_dir=str(policy_dir),
        )
        mw = GuardMiddleware(config)
        request = _make_request(
            body=_openai_request_body(
                messages=[
                    {"role": "user", "content": "password: hunter2"},
                ]
            )
        )

        await mw.handle_request(request)

        assert len(mw.audit_log.entries) == 1
        meta = mw.audit_log.entries[0].metadata
        assert "message_count" in meta
        assert meta["message_count"] == "1"

    @pytest.mark.anyio
    async def test_denied_request_has_token_estimate(self, policy_dir: Path) -> None:
        """Denied request audit should include token_estimate."""
        config = ProxyConfig(
            upstream_base_url="https://api.openai.com",
            policy_dir=str(policy_dir),
        )
        mw = GuardMiddleware(config)
        request = _make_request(
            body=_openai_request_body(
                messages=[
                    {"role": "user", "content": "password: hunter2"},
                ]
            )
        )

        await mw.handle_request(request)

        meta = mw.audit_log.entries[0].metadata
        assert "token_estimate" in meta
        assert int(meta["token_estimate"]) > 0

    @pytest.mark.anyio
    async def test_non_json_body_has_zero_message_count(
        self, base_config: ProxyConfig
    ) -> None:
        """Non-JSON body should have message_count=0 and token_estimate=0."""
        mw = GuardMiddleware(base_config)
        request = MagicMock()
        request.method = "POST"
        request.url.path = "/v1/audio/transcriptions"
        request.url.query = ""
        request.body = AsyncMock(return_value=b"binary audio data")
        request.headers = {
            "content-type": "multipart/form-data",
            "host": "localhost",
        }

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.content = b'{"text": "transcription"}'
        mock_response.headers = {"content-type": "application/json"}

        with patch.object(mw, "_forward_request", return_value=mock_response):
            await mw.handle_request(request)

        meta = mw.audit_log.entries[0].metadata
        assert meta["message_count"] == "0"
        assert meta["token_estimate"] == "0"

    @pytest.mark.anyio
    async def test_token_estimate_scales_with_content(
        self, base_config: ProxyConfig
    ) -> None:
        """Token estimate should be larger for longer messages."""
        mw = GuardMiddleware(base_config)
        short_messages = [{"role": "user", "content": "Hi"}]
        long_messages = [{"role": "user", "content": "Tell me a very long story " * 50}]

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.content = json.dumps({"choices": []}).encode()
        mock_response.headers = {"content-type": "application/json"}

        # Short request
        request_short = _make_request(
            body=_openai_request_body(messages=short_messages)
        )
        with patch.object(mw, "_forward_request", return_value=mock_response):
            await mw.handle_request(request_short)
        short_tokens = int(mw.audit_log.entries[-1].metadata["token_estimate"])

        # Long request
        request_long = _make_request(body=_openai_request_body(messages=long_messages))
        with patch.object(mw, "_forward_request", return_value=mock_response):
            await mw.handle_request(request_long)
        long_tokens = int(mw.audit_log.entries[-1].metadata["token_estimate"])

        assert long_tokens > short_tokens


# ===========================================================================
# Test: Streaming response scanning
# ===========================================================================


class TestStreamingResponseScanning:
    """Test inbound scanning of streaming LLM responses."""

    @pytest.mark.anyio
    async def test_streaming_with_scan_responses_creates_scanner(
        self, response_policy_dir: Path
    ) -> None:
        """When scan_responses=True and streaming, scanner should be used."""
        config = ProxyConfig(
            upstream_base_url="https://api.openai.com",
            policy_dir=str(response_policy_dir),
            scan_responses=True,
        )
        mw = GuardMiddleware(config)
        request = _make_request(body=_openai_request_body(stream=True))

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.headers = {"content-type": "text/event-stream"}

        # Simulate benign SSE lines
        async def fake_aiter_lines():
            lines = [
                'data: {"choices": [{"delta": {"content": "Hello"}}]}',
                'data: {"choices": [{"delta": {"content": " world"}}]}',
                "data: [DONE]",
            ]
            for line in lines:
                yield line

        mock_response.aiter_lines = fake_aiter_lines

        mock_client = AsyncMock()
        stream_ctx = _StreamContext(client=mock_client, response=mock_response)

        with patch.object(mw, "_forward_streaming", return_value=stream_ctx):
            response = await mw.handle_request(request)

        assert response.status_code == 200

    @pytest.mark.anyio
    async def test_streaming_scan_denial_audited(
        self, response_policy_dir: Path
    ) -> None:
        """Streaming scan denial should be recorded in the audit log."""
        config = ProxyConfig(
            upstream_base_url="https://api.openai.com",
            policy_dir=str(response_policy_dir),
            scan_responses=True,
        )
        mw = GuardMiddleware(config)
        request = _make_request(body=_openai_request_body(stream=True))

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.headers = {"content-type": "text/event-stream"}

        # SSE stream with harmful content
        async def fake_aiter_lines():
            lines = [
                'data: {"choices": [{"delta": {"content": "HARMFUL_CONTENT"}}]}',
                "data: [DONE]",
            ]
            for line in lines:
                yield line

        mock_response.aiter_lines = fake_aiter_lines

        mock_client = AsyncMock()
        stream_ctx = _StreamContext(client=mock_client, response=mock_response)

        with patch.object(mw, "_forward_streaming", return_value=stream_ctx):
            response = await mw.handle_request(request)

        # Should still return 200 (streaming response — denial is in-band)
        assert response.status_code == 200

        # Consume the streaming body to trigger the scanning
        body_chunks = []
        async for chunk in response.body_iterator:
            body_chunks.append(chunk)

        # Verify the stream contains the warning event
        full_body = b"".join(
            c if isinstance(c, bytes) else c.encode() for c in body_chunks
        )
        assert b"blocked" in full_body or b"error" in full_body

        # Check audit log — should have request allowed + response denied
        entries = mw.audit_log.entries
        response_entries = [e for e in entries if e.action == "llm_response"]
        assert len(response_entries) == 1
        assert response_entries[0].result == "denied"

    @pytest.mark.anyio
    async def test_streaming_scan_clean_stream_audited(
        self, response_policy_dir: Path
    ) -> None:
        """Clean streaming response should be audited as allowed."""
        config = ProxyConfig(
            upstream_base_url="https://api.openai.com",
            policy_dir=str(response_policy_dir),
            scan_responses=True,
        )
        mw = GuardMiddleware(config)
        request = _make_request(body=_openai_request_body(stream=True))

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.headers = {"content-type": "text/event-stream"}

        async def fake_aiter_lines():
            lines = [
                'data: {"choices": [{"delta": {"content": "safe"}}]}',
                'data: {"choices": [{"delta": {"content": " content"}}]}',
                "data: [DONE]",
            ]
            for line in lines:
                yield line

        mock_response.aiter_lines = fake_aiter_lines

        mock_client = AsyncMock()
        stream_ctx = _StreamContext(client=mock_client, response=mock_response)

        with patch.object(mw, "_forward_streaming", return_value=stream_ctx):
            response = await mw.handle_request(request)

        # Consume the streaming body to trigger the scanning
        async for _chunk in response.body_iterator:
            pass

        # Check audit log — should have request allowed + response allowed
        entries = mw.audit_log.entries
        response_entries = [e for e in entries if e.action == "llm_response"]
        assert len(response_entries) == 1
        assert response_entries[0].result == "allowed"
        assert "scanned_length" in response_entries[0].metadata

    @pytest.mark.anyio
    async def test_streaming_no_scan_responses_no_scanner(
        self, base_config: ProxyConfig
    ) -> None:
        """Without scan_responses, streaming should not create a scanner."""
        # base_config has scan_responses=False by default
        mw = GuardMiddleware(base_config)
        request = _make_request(body=_openai_request_body(stream=True))

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.headers = {"content-type": "text/event-stream"}

        async def fake_aiter_bytes():
            yield b"data: {}\n\n"

        mock_response.aiter_bytes = fake_aiter_bytes

        mock_client = MagicMock()
        stream_ctx = _StreamContext(client=mock_client, response=mock_response)

        with patch.object(mw, "_forward_streaming", return_value=stream_ctx):
            response = await mw.handle_request(request)

        assert response.status_code == 200
        # No response audit entries since scan_responses is False
        response_entries = [
            e for e in mw.audit_log.entries if e.action == "llm_response"
        ]
        assert len(response_entries) == 0


# ===========================================================================
# Test: Provider integration in middleware
# ===========================================================================


class TestProviderIntegration:
    """Test that middleware uses provider from config for param extraction."""

    @pytest.mark.anyio
    async def test_middleware_with_provider_config(self, policy_dir: Path) -> None:
        """Middleware with provider='openai' should use OpenAI provider."""
        config = ProxyConfig(
            upstream_base_url="https://api.openai.com",
            policy_dir=str(policy_dir),
            provider="openai",
        )
        mw = GuardMiddleware(config)
        assert mw.provider is not None
        assert mw.provider.name == "openai"

    @pytest.mark.anyio
    async def test_middleware_without_provider_config(
        self, base_config: ProxyConfig
    ) -> None:
        """Middleware without provider should use default (None → fallback)."""
        mw = GuardMiddleware(base_config)
        # When provider is None in config, middleware should still work
        request = _make_request(body=_openai_request_body())

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.content = json.dumps({"choices": []}).encode()
        mock_response.headers = {"content-type": "application/json"}

        with patch.object(mw, "_forward_request", return_value=mock_response):
            response = await mw.handle_request(request)

        assert response.status_code == 200

    @pytest.mark.anyio
    async def test_provider_used_for_request_scanning(self, policy_dir: Path) -> None:
        """Provider should be used for extracting request params."""
        config = ProxyConfig(
            upstream_base_url="https://api.openai.com",
            policy_dir=str(policy_dir),
            provider="openai",
        )
        mw = GuardMiddleware(config)
        request = _make_request(
            body=_openai_request_body(
                messages=[
                    {"role": "user", "content": "My password: secret123"},
                ]
            )
        )

        response = await mw.handle_request(request)
        # Should be denied by the policy
        assert response.status_code == 403

    @pytest.mark.anyio
    async def test_provider_used_for_response_scanning(
        self, response_policy_dir: Path
    ) -> None:
        """Provider should be used for extracting response params."""
        config = ProxyConfig(
            upstream_base_url="https://api.openai.com",
            policy_dir=str(response_policy_dir),
            scan_responses=True,
            provider="openai",
        )
        mw = GuardMiddleware(config)
        request = _make_request(body=_openai_request_body())

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.content = json.dumps(
            {"choices": [{"message": {"content": "HARMFUL_CONTENT here"}}]}
        ).encode()
        mock_response.headers = {"content-type": "application/json"}

        with patch.object(mw, "_forward_request", return_value=mock_response):
            response = await mw.handle_request(request)

        assert response.status_code == 403
