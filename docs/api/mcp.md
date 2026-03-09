# MCP Server API Reference

Transparent MCP proxy with policy enforcement and audit logging.

The MCP server exposes 7 action tools (`shell_execute`, `file_read`,
`file_write`, `file_edit`, `file_glob`, `file_grep`, `file_list`) and
2 introspection tools (`agentguard_status`, `agentguard_audit_query`)
that pass through AgentGuard's policy engine before execution. See the
[MCP Integration Guide](../guides/mcp-integration.md) for usage
instructions and client enforcement levels.

## create_server

Factory function that creates a configured MCP server instance.

::: agentguard.mcp.server.create_server
    options:
      show_source: true
