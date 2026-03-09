"""ASGI middleware for LLM API proxy with policy enforcement.

The GuardMiddleware intercepts incoming requests, extracts LLM
content from the request body, checks it against Guard policies,
and either denies (403) or forwards the request upstream.
"""

from __future__ import annotations

import json
import uuid
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from starlette.requests import Request
    from starlette.responses import Response

    from agentguard.proxy.config import ProxyConfig

from agentguard.audit.log import AuditLog
from agentguard.policies.guard import Guard


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
        """
        self.config = config
        self.guard = self._build_guard()
        self.session_id = f"proxy-{uuid.uuid4().hex[:12]}"
        self.audit_log = AuditLog(self.session_id)

    def _build_guard(self) -> Guard:
        """Build a Guard instance from the config."""
        guard = Guard()

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
            params = extract_request_params(body)
        except ValueError:
            # Non-JSON body — pass through without scanning
            params = {}

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

        try:
            is_streaming = self._is_streaming_request(body)

            if is_streaming:
                upstream_response = await self._forward_streaming(
                    request.method, upstream_url, headers, body
                )
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
            },
        )
        self._save_audit()

        if is_streaming:
            # Return streaming response
            response_headers = self._filter_response_headers(upstream_response.headers)
            return StreamingResponse(
                upstream_response.aiter_bytes(),
                status_code=upstream_response.status_code,
                headers=response_headers,
                media_type=upstream_response.headers.get(
                    "content-type", "text/event-stream"
                ),
            )

        # Non-streaming: optionally scan response
        response_body = upstream_response.content
        if self.config.scan_responses and response_body:
            try:
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
    ) -> Any:
        """Forward a streaming request to the upstream.

        Returns an httpx Response with stream NOT consumed, so the
        caller can iterate over it.
        """
        import httpx

        client = httpx.AsyncClient(timeout=self.config.timeout)
        response = await client.send(
            client.build_request(
                method=method,
                url=url,
                headers=headers,
                content=body,
            ),
            stream=True,
        )
        return response

    def _is_streaming_request(self, body: bytes) -> bool:
        """Check if the request asks for streaming."""
        try:
            data = json.loads(body)
            return isinstance(data, dict) and data.get("stream", False) is True
        except (json.JSONDecodeError, UnicodeDecodeError):
            return False

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
