"""ASGI middleware for LLM API proxy with policy enforcement.

The GuardMiddleware intercepts incoming requests, extracts LLM
content from the request body, checks it against Guard policies,
and either denies (403) or forwards the request upstream.
"""

from __future__ import annotations

import json
import uuid
from pathlib import Path
from typing import TYPE_CHECKING, Any, NamedTuple

if TYPE_CHECKING:
    from collections.abc import AsyncGenerator

    from starlette.requests import Request
    from starlette.responses import Response

    from agentguard.proxy.config import ProxyConfig
    from agentguard.proxy.providers import Provider

from agentguard.audit.log import AuditLog
from agentguard.policies.guard import Guard
from agentguard.proxy.outbound import estimate_tokens


class _StreamContext(NamedTuple):
    """Holds the httpx client and streaming response for cleanup."""

    client: Any  # httpx.AsyncClient
    response: Any  # httpx.Response


class GuardMiddleware:
    """Starlette middleware that enforces Guard policies on LLM requests.

    For each request:
    1. Reads the request body
    2. Extracts scannable content via the scanner module
    3. Checks content against loaded Guard policies
    4. If denied: returns 403 with denial details
    5. If allowed: forwards to upstream and returns the response
    6. Optionally scans the response content
    7. Records everything in the audit log

    Attributes:
        guard: The Guard instance with loaded policies.
        audit_log: The audit log for this session.
        config: Proxy configuration.
    """

    def __init__(self, config: ProxyConfig) -> None:
        """Initialize the middleware.

        Args:
            config: Proxy server configuration.

        Raises:
            ValueError: If the auth file is invalid JSON or the
                configured provider key is not found in the file.
        """
        self.config = config
        self.guard = self._build_guard()
        self.provider = self._resolve_provider()
        self._auth_token: str | None = self._load_auth_token()
        self.session_id = f"proxy-{uuid.uuid4().hex[:12]}"
        self.audit_log = AuditLog(self.session_id)

    def _load_auth_token(self) -> str | None:
        """Load an auth token from the configured auth file.

        Reads the JSON auth file and extracts a Bearer token for the
        configured provider.  Supports two token formats:

        - OAuth (e.g. GitHub Copilot): ``{"refresh": "gho_..."}``
        - API key (e.g. Anthropic): ``{"key": "sk-ant-..."}``

        Returns:
            The raw token string (without ``Bearer `` prefix), or
            None if no auth file is configured.

        Raises:
            ValueError: If the file contains invalid JSON or the
                configured provider key is not present.
        """
        if self.config.auth_file is None:
            return None

        auth_path = Path(self.config.auth_file)
        raw = auth_path.read_text(encoding="utf-8")
        try:
            data = json.loads(raw)
        except json.JSONDecodeError as exc:
            msg = f"Invalid JSON in auth file {self.config.auth_file}: {exc}"
            raise ValueError(msg) from exc

        if not isinstance(data, dict):
            type_name = type(data).__name__
            msg = f"Invalid JSON in auth file: expected object, got {type_name}"
            raise ValueError(msg) from None

        provider_key = self.config.auth_provider
        if provider_key not in data:
            msg = (
                f"Auth provider '{provider_key}' not found in "
                f"{self.config.auth_file}. "
                f"Available providers: {', '.join(data.keys())}"
            )
            raise ValueError(msg)

        provider_data = data[provider_key]
        if not isinstance(provider_data, dict):
            msg = (
                f"Auth provider '{provider_key}' value must be an object, "
                f"got {type(provider_data).__name__}"
            )
            raise ValueError(msg)

        # Try "refresh" (OAuth token), then "key" (API key)
        token = provider_data.get("refresh") or provider_data.get("key")
        if not token:
            msg = f"Auth provider '{provider_key}' has no 'refresh' or 'key' field"
            raise ValueError(msg)

        return str(token)

    def _inject_auth_headers(self, headers: dict[str, str]) -> None:
        """Replace or add the Authorization header with the loaded token.

        Modifies *headers* in place.  Does nothing if no auth token
        was loaded at init time.
        """
        if self._auth_token is not None:
            headers["authorization"] = f"Bearer {self._auth_token}"

    def _build_guard(self) -> Guard:
        """Build a Guard instance from the config.

        Policy sources are additive: each enabled source appends its
        policies to the guard.  The ``if`` blocks below are deliberately
        independent (not ``elif``) so that, for example, a preset can be
        combined with a policy directory or auto-discovery.  The only
        mutual exclusion is between ``preset`` and ``load_builtins``
        (validated below).
        """
        guard = Guard()

        if self.config.preset is not None and self.config.load_builtins:
            msg = "Cannot use both --preset and --builtins. Choose one."
            raise ValueError(msg)

        if self.config.preset is not None:
            from agentguard.policies.presets import load_preset

            for policy in load_preset(self.config.preset):
                guard.add_policy(policy)

        if self.config.policy_dir is not None:
            policy_path = Path(self.config.policy_dir)
            if not policy_path.is_dir():
                msg = f"Policy directory does not exist: {self.config.policy_dir}"
                raise FileNotFoundError(msg)
            for yaml_file in sorted(policy_path.glob("*.yaml")):
                guard.load_policy_file(yaml_file)

        if self.config.auto_discover:
            from agentguard.policies.discovery import auto_discover

            for policy in auto_discover():
                guard.add_policy(policy)

        if self.config.load_builtins:
            from agentguard.policies.builtins import load_all_builtins

            for policy in load_all_builtins():
                guard.add_policy(policy)

        return guard

    def _resolve_provider(self) -> Provider | None:
        """Resolve the provider adapter from the config.

        Returns:
            A Provider instance if configured, or None to use the
            legacy scanner module fallback.
        """
        if self.config.provider is not None:
            from agentguard.proxy.providers import detect_provider

            return detect_provider(provider_name=self.config.provider)
        return None

    async def handle_request(self, request: Request) -> Response:
        """Handle an incoming LLM API request.

        Args:
            request: The incoming Starlette request.

        Returns:
            Either a 403 denial response or the upstream response.
        """
        from starlette.responses import JSONResponse, StreamingResponse

        from agentguard.proxy.scanner import (
            extract_request_params,
            extract_response_params,
        )

        body = await request.body()
        path = request.url.path

        # Check allowed endpoints
        if self.config.allowed_endpoints and not any(
            path.startswith(ep) for ep in self.config.allowed_endpoints
        ):
            return JSONResponse(
                {"error": "endpoint not allowed", "path": path},
                status_code=404,
            )

        # Extract and scan request content
        try:
            if self.provider is not None:
                params = self.provider.extract_request_params(body)
            else:
                params = extract_request_params(body)
        except ValueError:
            # Non-JSON body — pass through without scanning
            params = {}

        # Parse JSON body once for stats and streaming detection,
        # avoiding redundant json.loads() calls.
        parsed_body = self._parse_body(body)
        message_count, token_est = self._extract_body_stats(parsed_body)

        if params:
            decision = self.guard.check("llm_request", **params)
            if decision.denied:
                self.audit_log.record(
                    action="llm_request",
                    actor=self.config.actor,
                    target=path,
                    result="denied",
                    metadata={
                        "denied_by": decision.denied_by or "",
                        "reason": decision.reason or "",
                        "message_count": str(message_count),
                        "token_estimate": str(token_est),
                    },
                )
                self._save_audit()
                return JSONResponse(
                    {
                        "error": "request denied by policy",
                        "denied_by": decision.denied_by,
                        "reason": decision.reason,
                    },
                    status_code=403,
                )

        # Forward to upstream
        import httpx

        upstream_url = self.config.upstream_base_url + path
        if request.url.query:
            upstream_url += "?" + request.url.query

        # Forward headers, replacing Host
        headers = dict(request.headers)
        headers.pop("host", None)
        headers.pop("content-length", None)

        # Inject auth token if configured
        self._inject_auth_headers(headers)

        try:
            is_streaming = self._is_streaming_request(parsed_body)

            if is_streaming:
                stream_ctx = await self._forward_streaming(
                    request.method, upstream_url, headers, body
                )
                upstream_response = stream_ctx.response
            else:
                upstream_response = await self._forward_request(
                    request.method, upstream_url, headers, body
                )
        except httpx.HTTPError as e:
            self.audit_log.record(
                action="llm_request",
                actor=self.config.actor,
                target=path,
                result="error",
                metadata={"error": str(e)},
            )
            self._save_audit()
            return JSONResponse(
                {"error": "upstream request failed", "detail": str(e)},
                status_code=502,
            )

        # Record allowed request
        self.audit_log.record(
            action="llm_request",
            actor=self.config.actor,
            target=path,
            result="allowed",
            metadata={
                "upstream_status": str(upstream_response.status_code),
                "model": params.get("model", ""),
                "message_count": str(message_count),
                "token_estimate": str(token_est),
            },
        )
        self._save_audit()

        if is_streaming:
            from starlette.background import BackgroundTask

            response_headers = self._filter_response_headers(upstream_response.headers)

            if self.config.scan_responses:
                # Use inbound scanner for streaming response scanning
                from agentguard.proxy.inbound import InboundScanner
                from agentguard.proxy.streaming import stream_sse_response

                scanner = InboundScanner(self.guard)

                async def _scanning_generator() -> AsyncGenerator[bytes, None]:
                    try:
                        async for chunk_bytes, _collected in stream_sse_response(
                            upstream_response, scanner=scanner, provider=self.provider
                        ):
                            yield chunk_bytes

                        # Stream finished — record audit
                        result = scanner.finalize()
                        if result.denied:
                            self.audit_log.record(
                                action="llm_response",
                                actor=self.config.actor,
                                target=path,
                                result="denied",
                                metadata={
                                    "denied_by": result.denied_by or "",
                                    "reason": result.reason or "",
                                    "scanned_length": str(result.scanned_length),
                                    "token_estimate": str(result.token_estimate),
                                },
                            )
                        else:
                            self.audit_log.record(
                                action="llm_response",
                                actor=self.config.actor,
                                target=path,
                                result="allowed",
                                metadata={
                                    "scanned_length": str(result.scanned_length),
                                    "token_estimate": str(result.token_estimate),
                                },
                            )
                        self._save_audit()
                    except Exception:
                        # Record audit even when the stream fails
                        self.audit_log.record(
                            action="llm_response",
                            actor=self.config.actor,
                            target=path,
                            result="error",
                            metadata={"error": "stream iteration failed"},
                        )
                        self._save_audit()
                        raise

                cleanup = BackgroundTask(
                    self._cleanup_stream, stream_ctx.client, stream_ctx.response
                )
                return StreamingResponse(
                    _scanning_generator(),
                    status_code=upstream_response.status_code,
                    headers=response_headers,
                    media_type=upstream_response.headers.get(
                        "content-type", "text/event-stream"
                    ),
                    background=cleanup,
                )

            # No response scanning — forward raw bytes
            cleanup = BackgroundTask(
                self._cleanup_stream, stream_ctx.client, stream_ctx.response
            )
            return StreamingResponse(
                upstream_response.aiter_bytes(),
                status_code=upstream_response.status_code,
                headers=response_headers,
                media_type=upstream_response.headers.get(
                    "content-type", "text/event-stream"
                ),
                background=cleanup,
            )

        # Non-streaming: optionally scan response
        response_body = upstream_response.content
        if self.config.scan_responses and response_body:
            try:
                if self.provider is not None:
                    response_params = self.provider.extract_response_params(
                        response_body
                    )
                else:
                    response_params = extract_response_params(response_body)
                if response_params:
                    response_decision = self.guard.check(
                        "llm_response", **response_params
                    )
                    if response_decision.denied:
                        self.audit_log.record(
                            action="llm_response",
                            actor=self.config.actor,
                            target=path,
                            result="denied",
                            metadata={
                                "denied_by": response_decision.denied_by or "",
                                "reason": response_decision.reason or "",
                            },
                        )
                        self._save_audit()
                        return JSONResponse(
                            {
                                "error": "response denied by policy",
                                "denied_by": response_decision.denied_by,
                                "reason": response_decision.reason,
                            },
                            status_code=403,
                        )
            except ValueError:
                pass

        response_headers = self._filter_response_headers(upstream_response.headers)
        from starlette.responses import Response as StarletteResponse

        return StarletteResponse(
            content=response_body,
            status_code=upstream_response.status_code,
            headers=response_headers,
            media_type=upstream_response.headers.get("content-type"),
        )

    def _extract_body_stats(self, parsed: dict[str, Any] | None) -> tuple[int, int]:
        """Extract message count and token estimate from parsed request body.

        Args:
            parsed: Pre-parsed JSON body dict, or None if body was
                not valid JSON.

        Returns:
            Tuple of (message_count, token_estimate).
            Both are 0 if the body is None or has no messages.
        """
        if parsed is None:
            return 0, 0

        messages = parsed.get("messages")
        if not isinstance(messages, list):
            return 0, 0

        message_count = len(messages)

        # Concatenate all message content for token estimation
        content_parts: list[str] = []
        for msg in messages:
            if isinstance(msg, dict):
                content = msg.get("content", "")
                if isinstance(content, str):
                    content_parts.append(content)
                elif isinstance(content, list):
                    # OpenAI structured content blocks:
                    # [{"type": "text", "text": "..."}, ...]
                    for block in content:
                        if isinstance(block, dict):
                            text = block.get("text")
                            if isinstance(text, str):
                                content_parts.append(text)
        all_content = " ".join(content_parts)
        token_est = estimate_tokens(all_content)

        return message_count, token_est

    @staticmethod
    def _parse_body(body: bytes) -> dict[str, Any] | None:
        """Parse the raw request body as JSON.

        Returns the parsed dict if the body is valid JSON and
        contains an object.  Returns None otherwise.
        """
        try:
            data = json.loads(body)
        except (json.JSONDecodeError, UnicodeDecodeError):
            return None
        if isinstance(data, dict):
            return data
        return None

    async def _forward_request(
        self,
        method: str,
        url: str,
        headers: dict[str, str],
        body: bytes,
    ) -> Any:
        """Forward a non-streaming request to the upstream."""
        import httpx

        async with httpx.AsyncClient(timeout=self.config.timeout) as client:
            return await client.request(
                method=method,
                url=url,
                headers=headers,
                content=body,
            )

    async def _forward_streaming(
        self,
        method: str,
        url: str,
        headers: dict[str, str],
        body: bytes,
    ) -> _StreamContext:
        """Forward a streaming request to the upstream.

        Returns a _StreamContext containing the httpx client and
        Response with stream NOT consumed, so the caller can iterate
        over it.  The caller MUST ensure both are closed when done
        (via _cleanup_stream).
        """
        import httpx

        client = httpx.AsyncClient(timeout=self.config.timeout)
        try:
            response = await client.send(
                client.build_request(
                    method=method,
                    url=url,
                    headers=headers,
                    content=body,
                ),
                stream=True,
            )
        except Exception:
            await client.aclose()
            raise
        return _StreamContext(client=client, response=response)

    @staticmethod
    async def _cleanup_stream(client: Any, response: Any) -> None:
        """Close the streaming response and httpx client.

        Attached as a BackgroundTask to StreamingResponse so cleanup
        happens after the response body has been fully sent.
        """
        await response.aclose()
        await client.aclose()

    def _is_streaming_request(self, parsed: dict[str, Any] | None) -> bool:
        """Check if the request asks for streaming."""
        return isinstance(parsed, dict) and parsed.get("stream", False) is True

    def _filter_response_headers(self, headers: Any) -> dict[str, str]:
        """Filter upstream response headers for forwarding.

        Removes hop-by-hop headers that shouldn't be forwarded.
        """
        hop_by_hop = {
            "connection",
            "keep-alive",
            "proxy-authenticate",
            "proxy-authorization",
            "te",
            "trailers",
            "transfer-encoding",
            "upgrade",
        }
        return {k: v for k, v in headers.items() if k.lower() not in hop_by_hop}

    def _save_audit(self) -> None:
        """Append new audit entries to disk if configured."""
        if self.config.audit_dir is not None:
            audit_path = Path(self.config.audit_dir)
            audit_path.mkdir(parents=True, exist_ok=True)
            self.audit_log.append(audit_path / f"{self.session_id}.jsonl")
