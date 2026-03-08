"""Entry point for ``python -m agentguard.mcp``.

Starts an AgentGuard MCP server with built-in policies and
auto-discovery enabled. For more control over server options,
use the CLI: ``agentguard serve --help``.
"""

from __future__ import annotations

from agentguard.mcp.server import create_server

app = create_server(
    load_builtins=True,
    auto_discover=True,
)
app.run()
