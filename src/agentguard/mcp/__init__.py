"""AgentGuard MCP Server -- transparent proxy with policy enforcement.

This module provides an MCP (Model Context Protocol) server that exposes
shell execution, file read, and file write tools. Every tool call passes
through AgentGuard's policy engine before execution and is recorded in
a tamper-evident audit log.

Usage::

    python -m agentguard.mcp --policies policies/

Or in opencode.json::

    {
        "mcpServers": {
            "agentguard": {
                "type": "local",
                "command": "python",
                "args": ["-m", "agentguard.mcp", "--policies", "policies/"]
            }
        }
    }
"""
