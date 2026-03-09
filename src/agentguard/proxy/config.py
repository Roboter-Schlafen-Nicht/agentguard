"""Proxy configuration.

ProxyConfig holds all settings needed to create and run the
LLM API proxy server.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class ProxyConfig:
    """Configuration for the LLM API proxy server.

    Attributes:
        upstream_base_url: Base URL of the upstream LLM API
            (e.g. ``https://api.openai.com``). Required.
        host: Address to bind the proxy server to.
        port: Port to bind the proxy server to.
        policy_dir: Directory containing YAML policy files.
        audit_dir: Directory where audit logs are saved. If None,
            audit entries are kept in memory only.
        actor: Actor name recorded in audit entries.
        load_builtins: Whether to load built-in policies.
        auto_discover: Whether to auto-discover policies from
            standard locations.
        scan_responses: Whether to also scan upstream responses
            against policies. Default False (only scan requests).
        timeout: Timeout in seconds for upstream requests.
        allowed_endpoints: URL path patterns that are proxied.
            Requests to other paths get 404. If empty, all paths
            are proxied.
    """

    upstream_base_url: str
    host: str = "127.0.0.1"
    port: int = 8080
    policy_dir: str | None = None
    audit_dir: str | None = None
    actor: str = "llm-proxy"
    load_builtins: bool = False
    auto_discover: bool = False
    scan_responses: bool = False
    timeout: float = 120.0
    allowed_endpoints: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        """Validate configuration."""
        if not self.upstream_base_url:
            msg = "upstream_base_url is required"
            raise ValueError(msg)
        # Strip trailing slash for consistent URL joining
        self.upstream_base_url = self.upstream_base_url.rstrip("/")
        if self.port < 1 or self.port > 65535:
            msg = f"port must be 1-65535, got {self.port}"
            raise ValueError(msg)
        if self.timeout <= 0:
            msg = f"timeout must be positive, got {self.timeout}"
            raise ValueError(msg)
