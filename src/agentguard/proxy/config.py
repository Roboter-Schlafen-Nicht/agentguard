"""Proxy configuration.

ProxyConfig holds all settings needed to create and run the
LLM API proxy server.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from agentguard.audit.retention import RetentionConfig
    from agentguard.audit.rotation import RotationConfig
    from agentguard.proxy.compaction.config import CompactionConfig
    from agentguard.proxy.routing.config import RoutingConfig


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
        preset: Named protection level preset to load
            (``"strict"``, ``"balanced"``, or ``"permissive"``).
            Mutually exclusive with ``load_builtins``.
        scan_responses: Whether to also scan upstream responses
            against policies. Default False (only scan requests).
        timeout: Timeout in seconds for upstream requests.
        allowed_endpoints: URL path patterns that are proxied.
            Requests to other paths get 404. If empty, all paths
            are proxied.
        provider: Name of the LLM API provider adapter to use
            for parsing request/response bodies (e.g. ``"openai"``).
            If None, falls back to the legacy ``scanner`` module
            which uses OpenAI-compatible format parsing.
        auth_file: Path to a JSON auth credentials file. When set,
            the proxy reads a Bearer token from this file and
            injects it into the ``Authorization`` header of upstream
            requests, replacing any token sent by the client. This
            allows the proxy to handle authentication on behalf of
            clients that don't have direct access to the upstream
            credentials. File format: ``{"<provider>": {"refresh":
            "<token>", ...}}`` (OpenCode auth.json format).
        auth_provider: Provider key to look up in the auth file.
            Defaults to ``"github-copilot"``.
        rotation: Optional audit log rotation config. When set,
            audit files are rotated when they exceed size or age
            thresholds.
        retention: Optional audit log retention config. When set,
            old rotated files are deleted after rotation based on
            file count, age, or total size limits.
        delta_scanning: When True, the proxy tracks which messages
            in a conversation have already been scanned and only
            scans new/unseen messages on subsequent requests.
            Default False for backward compatibility.
        compaction: Optional context compaction config. When set
            and enabled, large conversations are compressed
            (truncation + summarization) before forwarding to
            the upstream LLM API.
        routing: Optional model routing config. When set and
            enabled, requests are automatically routed to different
            models based on complexity (token count, message count,
            content patterns). Simple requests go to fast/cheap
            models; complex requests go to premium models.
    """

    upstream_base_url: str
    host: str = "127.0.0.1"
    port: int = 8080
    policy_dir: str | None = None
    audit_dir: str | None = None
    actor: str = "llm-proxy"
    load_builtins: bool = False
    auto_discover: bool = False
    preset: str | None = None
    scan_responses: bool = False
    timeout: float = 120.0
    allowed_endpoints: list[str] = field(default_factory=list)
    provider: str | None = None
    auth_file: str | None = None
    auth_provider: str = "github-copilot"
    rotation: RotationConfig | None = None
    retention: RetentionConfig | None = None
    delta_scanning: bool = False
    compaction: CompactionConfig | None = None
    routing: RoutingConfig | None = None

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
        if self.auth_file is not None and not Path(self.auth_file).is_file():
            msg = f"auth_file does not exist: {self.auth_file}"
            raise FileNotFoundError(msg)
