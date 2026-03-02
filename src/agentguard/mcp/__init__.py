"""AgentGuard MCP Server -- transparent proxy with policy enforcement.

This module provides an MCP (Model Context Protocol) server that exposes
shell execution, file read, and file write tools. Every tool call passes
through AgentGuard's policy engine before execution and is recorded in
a tamper-evident audit log.

Programmatic usage::

    from agentguard.mcp.server import create_server

    app = create_server(policy_dir="policies/", load_builtins=True)

Refer to the project documentation for details on how to start and
configure the MCP server with different MCP clients.
"""
