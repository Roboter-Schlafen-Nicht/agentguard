# MCP Server API Reference

Transparent MCP proxy with policy enforcement and audit logging.

The MCP server exposes agent tools (`shell_execute`, `file_read`,
`file_write`) that pass through AgentGuard's policy engine before
execution. See the [MCP Integration Guide](../guides/mcp-integration.md)
for usage instructions.

## create_server

Factory function that creates a configured MCP server instance.

::: agentguard.mcp.server.create_server
    options:
      show_source: true
