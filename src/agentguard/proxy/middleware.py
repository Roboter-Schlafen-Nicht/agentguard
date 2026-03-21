"""ASGI middleware for LLM API proxy with policy enforcement.

The GuardMiddleware intercepts incoming requests, extracts LLM
content from the request body, checks it against Guard policies,
and either denies (403) or forwards the request upstream.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from pathlib import Path
from typing import TYPE_CHECKING, Any, NamedTuple

if TYPE_CHECKING:
    from collections.abc import AsyncGenerator

    from starlette.requests import Request
    from starlette.responses import Response

    from agentguard.audit.log import AuditLog
    from agentguard.proxy.compaction.engine import CompactionEngine
    from agentguard.proxy.config import ProxyConfig
    from agentguard.proxy.providers import Provider
    from agentguard.proxy.routing.classifier import DifficultyClassifier
    from agentguard.proxy.routing.router import Router

from agentguard.audit.unified import Source, SourceAuditLog
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
        self.audit_log: AuditLog = SourceAuditLog(self.session_id, source=Source.PROXY)
        # Delta scanning: track how many messages have been scanned
        # per conversation, keyed by conversation fingerprint.
        self._seen_messages: dict[str, int] = {}
        # Context compaction engine (optional)
        self.compaction_engine = self._build_compaction_engine()
        # Model routing (optional)
        self.router = self._build_router()
        # Difficulty classifier (optional, requires routing + URL)
        self._classifier = self._build_classifier()

    def _build_compaction_engine(self) -> CompactionEngine | None:
        """Build a CompactionEngine if compaction is configured and enabled.

        Returns:
            A CompactionEngine instance, or None if compaction is
            not configured or is disabled.
        """
        if self.config.compaction is not None and self.config.compaction.enabled:
            from agentguard.proxy.compaction.engine import CompactionEngine

            return CompactionEngine(self.config.compaction)
        return None

    def _build_router(self) -> Router | None:
        """Build a Router if routing is configured and enabled.

        Returns:
            A Router instance, or None if routing is not configured.
        """
        if self.config.routing is not None:
            from agentguard.proxy.routing.router import Router

            return Router(self.config.routing)
        return None

    def _build_classifier(self) -> DifficultyClassifier | None:
        """Build a DifficultyClassifier if routing has a classifier URL.

        Returns:
            A DifficultyClassifier instance, or None if no classifier
            URL is configured.
        """
        if self.config.routing is not None and self.config.routing.classifier_url:
            from agentguard.proxy.routing.classifier import (
                DifficultyClassifier,
            )

            return DifficultyClassifier(
                url=self.config.routing.classifier_url,
            )
        return None

    async def _apply_routing(
        self,
        body: bytes,
    ) -> tuple[bytes, Any]:
        """Apply model routing to the request body.

        Parses the body, evaluates routing rules, and rewrites the
        model field if a routing decision is made.  When a difficulty
        classifier is configured, classifies the request content and
        passes the difficulty level to the router.

        Args:
            body: The raw request body bytes.

        Returns:
            Tuple of (possibly-modified body bytes, RoutingDecision).
            If routing is disabled or the body is not JSON, returns
            the original body with a passthrough decision.
        """
        from agentguard.proxy.routing.router import RoutingDecision

        passthrough = RoutingDecision(
            tier_name="passthrough",
            model=None,
            upstream_url=None,
            reason="No router configured",
        )

        if self.router is None:
            return body, passthrough

        try:
            parsed = json.loads(body)
        except (json.JSONDecodeError, UnicodeDecodeError):
            return body, passthrough

        if not isinstance(parsed, dict):
            return body, passthrough

        # Extract routing inputs
        messages = parsed.get("messages")
        if not isinstance(messages, list):
            return body, passthrough

        message_count = len(messages)

        # Concatenate message content for pattern matching and
        # token estimation
        all_content = self._concatenate_message_content(messages)
        token_est = estimate_tokens(all_content)

        # Classify difficulty if classifier is configured.
        # Extract only the last human user message for classification,
        # skipping tool calls and tool results.  In agentic sessions,
        # the tail of the conversation is tool_use/tool_result chatter
        # (code, diffs, CI logs) that the classifier misreads as
        # Complex.  The actual user intent is in the last real human
        # message.
        difficulty = 0
        classifier_input = ""
        if self._classifier is not None:
            classifier_input = self._extract_last_user_message(messages)
            difficulty = await self._classifier.classify(classifier_input)

        # Route the request
        decision = self.router.route(
            token_estimate=token_est,
            message_count=message_count,
            content=all_content,
            difficulty=difficulty,
        )

        # Attach classified text to the decision for audit logging.
        # The router doesn't know about classifier input — only the
        # middleware extracts it.  We use dataclasses.replace since
        # RoutingDecision is frozen.
        if classifier_input:
            from dataclasses import replace

            decision = replace(decision, classified_text=classifier_input)

        # Rewrite model if the decision specifies one
        if decision.model is not None:
            parsed["model"] = decision.model
            body = json.dumps(parsed).encode("utf-8")

        return body, decision

    @staticmethod
    def _routing_audit_metadata(decision: Any) -> dict[str, str]:
        """Build audit metadata from a routing decision.

        Args:
            decision: A RoutingDecision instance.

        Returns:
            Dict of string key-value pairs for audit logging.
        """
        metadata: dict[str, str] = {
            "routing_tier": str(decision.tier_name),
        }
        if decision.model is not None:
            metadata["routing_model"] = str(decision.model)
        if decision.upstream_url is not None:
            metadata["routing_upstream"] = str(decision.upstream_url)
        if decision.reason:
            metadata["routing_reason"] = str(decision.reason)
        if decision.classified_text:
            metadata["classified_text"] = decision.classified_text
        return metadata

    async def _compact_request_body(
        self,
        body: bytes,
    ) -> tuple[bytes, dict[str, Any]]:
        """Compact the request body if compaction is enabled.

        Parses the JSON body, extracts the messages array, runs
        compaction, and returns the re-serialized body with metrics.

        Args:
            body: The raw request body bytes.

        Returns:
            Tuple of (possibly-compacted body bytes, metrics dict).
            If compaction is disabled or the body has no messages,
            the original body is returned unchanged.
        """
        disabled_metrics: dict[str, Any] = {
            "phase_used": "disabled",
            "tokens_before": 0,
            "tokens_after": 0,
        }

        if self.compaction_engine is None:
            return body, disabled_metrics

        try:
            parsed = json.loads(body)
        except (json.JSONDecodeError, UnicodeDecodeError):
            return body, disabled_metrics

        if not isinstance(parsed, dict):
            return body, disabled_metrics

        messages = parsed.get("messages")
        if not isinstance(messages, list):
            return body, disabled_metrics

        result = await self.compaction_engine.compact(messages)

        metrics: dict[str, Any] = {
            "phase_used": result.phase_used,
            "tokens_before": result.tokens_before,
            "tokens_after": result.tokens_after,
            "messages_before": result.messages_before,
            "messages_after": result.messages_after,
            "summarizer_success": result.summarizer_success,
        }

        if result.phase_used in ("disabled", "none"):
            return body, metrics

        # Replace messages in the parsed body and re-serialize
        parsed["messages"] = result.messages
        compacted_body = json.dumps(parsed).encode("utf-8")
        return compacted_body, metrics

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

        # Context compaction: compress the conversation before
        # scanning and forwarding, if enabled.
        compaction_metrics: dict[str, Any] = {}
        body, compaction_metrics = await self._compact_request_body(body)

        # Model routing: select model/upstream based on complexity
        routing_decision = None
        body, routing_decision = await self._apply_routing(body)
        upstream_override = routing_decision.upstream_url

        # Check allowed endpoints
        if self.config.allowed_endpoints and not any(
            path.startswith(ep) for ep in self.config.allowed_endpoints
        ):
            return JSONResponse(
                {"error": "endpoint not allowed", "path": path},
                status_code=404,
            )

        # Extract and scan request content
        #
        # Delta scanning: when enabled, compute a conversation
        # fingerprint from the first message and only extract
        # messages that haven't been scanned yet.
        conv_fingerprint: str | None = None
        seen_count: int | None = None
        current_msg_count = 0

        try:
            parsed_body = self._parse_body(body)
            if (
                self.config.delta_scanning
                and parsed_body is not None
                and isinstance(parsed_body.get("messages"), list)
            ):
                messages_list = parsed_body["messages"]
                current_msg_count = len(messages_list)
                conv_fingerprint = self._conversation_fingerprint(messages_list)
                if conv_fingerprint is not None:
                    seen_count = self._seen_messages.get(conv_fingerprint, 0)

            if self.provider is not None:
                if seen_count is not None:
                    params = self.provider.extract_request_params(
                        body, seen_count=seen_count
                    )
                else:
                    params = self.provider.extract_request_params(body)
            else:
                params = extract_request_params(body)
        except ValueError:
            # Non-JSON body — pass through without scanning
            params = {}
            parsed_body = None

        # Parse JSON body for stats and streaming detection
        # (reuse parsed_body if we already have it).
        if parsed_body is None:
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

        # Delta scanning: update seen count after successful scan
        if conv_fingerprint is not None and current_msg_count > 0:
            self._seen_messages[conv_fingerprint] = current_msg_count

        # Use routing upstream override if set
        upstream_base = (
            upstream_override.rstrip("/")
            if upstream_override
            else self.config.upstream_base_url
        )
        upstream_url = upstream_base + path
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
        audit_metadata: dict[str, str] = {
            "upstream_status": str(upstream_response.status_code),
            "model": params.get("model", ""),
            "message_count": str(message_count),
            "token_estimate": str(token_est),
        }
        if compaction_metrics:
            audit_metadata["compaction_phase"] = str(
                compaction_metrics.get("phase_used", "")
            )
            audit_metadata["compaction_tokens_before"] = str(
                compaction_metrics.get("tokens_before", 0)
            )
            audit_metadata["compaction_tokens_after"] = str(
                compaction_metrics.get("tokens_after", 0)
            )
            summarizer_success = compaction_metrics.get("summarizer_success")
            if summarizer_success is not None:
                audit_metadata["compaction_summarizer_success"] = str(
                    summarizer_success
                )
        if routing_decision is not None:
            audit_metadata.update(self._routing_audit_metadata(routing_decision))
        self.audit_log.record(
            action="llm_request",
            actor=self.config.actor,
            target=path,
            result="allowed",
            metadata=audit_metadata,
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
        all_content = self._concatenate_message_content(messages)
        token_est = estimate_tokens(all_content)

        return message_count, token_est

    @staticmethod
    def _concatenate_message_content(messages: list[Any]) -> str:
        """Concatenate text content from all messages.

        Handles both simple string content and OpenAI structured
        content blocks (``[{"type": "text", "text": "..."}]``).

        Args:
            messages: The messages array from the request body.

        Returns:
            Space-joined string of all text content.
        """
        parts: list[str] = []
        for msg in messages:
            if isinstance(msg, dict):
                content = msg.get("content", "")
                if isinstance(content, str):
                    parts.append(content)
                elif isinstance(content, list):
                    for block in content:
                        if isinstance(block, dict):
                            text = block.get("text")
                            if isinstance(text, str):
                                parts.append(text)
        return " ".join(parts)

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
            self.audit_log.append(
                audit_path / f"{self.session_id}.jsonl",
                rotation=self.config.rotation,
                retention=self.config.retention,
            )

    @staticmethod
    def _extract_last_user_message(messages: list[Any]) -> str:
        """Extract the content of the last human user message.

        Walks the messages list in reverse and returns the text of
        the most recent message that is a real human input — not a
        tool result or assistant message.

        Detection rules:
        - OpenAI format: ``role="tool"`` → skip (tool result)
        - OpenAI format: ``role="assistant"`` → skip
        - OpenAI format: ``role="system"`` → skip
        - Anthropic format: ``role="user"`` with content containing
          ``{type: "tool_result"}`` blocks → skip
        - ``role="user"`` with string content → real human message
        - ``role="user"`` with list content containing only
          ``{type: "text"}`` blocks → real human message

        Args:
            messages: The messages array from the request body.

        Returns:
            The text content of the last human message, or empty
            string if no human message is found.
        """
        for msg in reversed(messages):
            if not isinstance(msg, dict):
                continue

            role = msg.get("role", "")

            # Skip non-user roles
            if role != "user":
                continue

            content = msg.get("content")

            # String content — always a real human message
            if isinstance(content, str):
                return content

            # List content — check for tool_result blocks (Anthropic)
            if isinstance(content, list):
                has_tool_result = any(
                    isinstance(block, dict) and block.get("type") == "tool_result"
                    for block in content
                )
                if has_tool_result:
                    continue  # Skip tool_result messages

                # Extract text from text blocks
                text_parts: list[str] = []
                for block in content:
                    if isinstance(block, dict):
                        text = block.get("text")
                        if isinstance(text, str):
                            text_parts.append(text)
                if text_parts:
                    return " ".join(text_parts)

        return ""

    @staticmethod
    def _conversation_fingerprint(messages: list[Any]) -> str | None:
        """Compute a fingerprint for a conversation from its first message.

        The fingerprint is a SHA-256 hex digest of the first message's
        role and content.  This lets the middleware identify the same
        conversation across successive requests (where earlier messages
        form a stable prefix).

        Args:
            messages: The messages array from the request body.

        Returns:
            A hex digest string, or None if the messages list is empty
            or the first message has no usable content.
        """
        if not messages:
            return None
        first = messages[0]
        if not isinstance(first, dict):
            return None
        role = first.get("role", "")
        content = first.get("content", "")
        if isinstance(content, list):
            # Structured content blocks — serialize for fingerprinting
            content = json.dumps(content, sort_keys=True)
        if not isinstance(content, str):
            content = str(content)
        raw = f"{role}:{content}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]
