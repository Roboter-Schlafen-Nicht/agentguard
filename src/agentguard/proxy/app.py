"""ASGI application factory for the LLM API proxy.

Creates a Starlette ASGI app that routes all requests through
the GuardMiddleware for policy enforcement and audit logging.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from starlette.applications import Starlette

    from agentguard.proxy.config import ProxyConfig


def create_app(config: ProxyConfig) -> Starlette:
    """Create the ASGI proxy application.

    Args:
        config: Proxy server configuration.

    Returns:
        A Starlette ASGI application.

    Raises:
        ImportError: If starlette is not installed.
    """
    from starlette.applications import Starlette
    from starlette.requests import Request  # noqa: TC002
    from starlette.responses import JSONResponse
    from starlette.routing import Route

    from agentguard.proxy.middleware import GuardMiddleware

    middleware_instance = GuardMiddleware(config)

    async def proxy_handler(request: Request) -> JSONResponse:
        """Handle all incoming requests via the guard middleware."""
        return await middleware_instance.handle_request(request)  # type: ignore[return-value]

    async def health(request: Request) -> JSONResponse:
        """Health check endpoint."""
        return JSONResponse(
            {
                "status": "ok",
                "session_id": middleware_instance.session_id,
                "policies_loaded": len(middleware_instance.guard.policies),
                "upstream": config.upstream_base_url,
            }
        )

    async def status(request: Request) -> JSONResponse:
        """Proxy status endpoint."""
        return JSONResponse(
            {
                "session_id": middleware_instance.session_id,
                "actor": config.actor,
                "policies_loaded": len(middleware_instance.guard.policies),
                "policy_names": [p.name for p in middleware_instance.guard.policies],
                "audit_entries": len(middleware_instance.audit_log.entries),
                "upstream": config.upstream_base_url,
                "scan_responses": config.scan_responses,
            }
        )

    routes = [
        Route("/_health", health, methods=["GET"]),
        Route("/_status", status, methods=["GET"]),
        Route(
            "/{path:path}",
            proxy_handler,
            methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
        ),
    ]

    app = Starlette(routes=routes)

    # Attach middleware instance for test access
    app.state.middleware = middleware_instance

    return app
