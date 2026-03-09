"""Run the LLM API proxy server as ``python -m agentguard.proxy``."""

from __future__ import annotations

import argparse
import sys


def main() -> int:
    """Entry point for ``python -m agentguard.proxy``."""
    try:
        import uvicorn
    except ImportError:
        print(
            "Error: Proxy dependencies not installed. "
            "Install with: pip install agentguard[proxy]",
            file=sys.stderr,
        )
        return 1

    from agentguard.proxy.app import create_app
    from agentguard.proxy.config import ProxyConfig

    parser = argparse.ArgumentParser(
        prog="agentguard-proxy",
        description="LLM API proxy with policy enforcement and audit logging.",
    )
    parser.add_argument(
        "upstream",
        help="Base URL of the upstream LLM API (e.g. https://api.openai.com).",
    )
    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="Host to bind to (default: 127.0.0.1).",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8080,
        help="Port to bind to (default: 8080).",
    )
    parser.add_argument(
        "--builtins",
        action="store_true",
        help="Load all built-in policies.",
    )
    parser.add_argument(
        "--auto-discover",
        action="store_true",
        help="Auto-discover policies from standard locations.",
    )
    parser.add_argument(
        "--policy-dir",
        help="Directory containing policy YAML files.",
    )
    parser.add_argument(
        "--audit-dir",
        help="Directory where audit logs are saved.",
    )
    parser.add_argument(
        "--actor",
        default="llm-proxy",
        help="Actor name for audit entries (default: llm-proxy).",
    )
    parser.add_argument(
        "--scan-responses",
        action="store_true",
        help="Also scan upstream responses against policies.",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=120.0,
        help="Timeout in seconds for upstream requests (default: 120).",
    )

    args = parser.parse_args()

    config = ProxyConfig(
        upstream_base_url=args.upstream,
        host=args.host,
        port=args.port,
        policy_dir=args.policy_dir,
        audit_dir=args.audit_dir,
        actor=args.actor,
        load_builtins=args.builtins,
        auto_discover=args.auto_discover,
        scan_responses=args.scan_responses,
        timeout=args.timeout,
    )

    app = create_app(config)
    uvicorn.run(app, host=config.host, port=config.port)
    return 0


if __name__ == "__main__":
    sys.exit(main())
