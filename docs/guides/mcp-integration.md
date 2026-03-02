# MCP Integration

AgentGuard ships an [MCP](https://modelcontextprotocol.io/) server that
acts as a transparent safety proxy for AI agents. Every tool call passes
through the policy engine and is recorded in a tamper-evident audit log.

## How it works

```
Agent  ──►  AgentGuard MCP Server  ──►  System
               │                           │
               ├── policy check ◄──────────┘
               └── audit log
```

The MCP server exposes three action tools (`shell_execute`, `file_read`,
`file_write`) and two introspection tools (`agentguard_status`,
`agentguard_audit_query`). When an agent calls a tool:

1. The request is checked against all loaded policies.
2. If denied, a `ToolError` is raised and the denial is logged.
3. If allowed, the action executes and the result is logged.

## Claude Desktop setup

Add AgentGuard to your Claude Desktop configuration
(`claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "agentguard": {
      "command": "uvx",
      "args": [
        "agentguard",
        "--policy-dir", "./policies",
        "--audit-dir", "./audit-logs",
        "--load-builtins"
      ]
    }
  }
}
```

Or if installed locally with `pip`:

```json
{
  "mcpServers": {
    "agentguard": {
      "command": "python",
      "args": [
        "-m", "agentguard.mcp",
        "--policy-dir", "./policies",
        "--audit-dir", "./audit-logs",
        "--load-builtins"
      ]
    }
  }
}
```

## Programmatic usage

Create an MCP server instance in Python:

```python
from agentguard.mcp.server import create_server

app = create_server(
    policy_dir="./policies",
    audit_dir="./audit-logs",
    actor="my-agent",
    load_builtins=True,
)
```

### Parameters

| Parameter | Type | Default | Description |
|---|---|---|---|
| `policy_dir` | `str \| None` | `None` | Directory containing YAML policy files. |
| `audit_dir` | `str \| None` | `None` | Directory for audit log output. If `None`, logs stay in memory. |
| `actor` | `str` | `"agent"` | Actor name recorded in audit entries. |
| `load_builtins` | `bool` | `False` | Load AgentGuard's built-in policies. |

## Available tools

### `shell_execute`

Execute a shell command. The command is checked against policies before
execution. Commands time out after 30 seconds.

```
shell_execute(command="ls -la")
```

### `file_read`

Read a text file. Binary files are rejected automatically.

```
file_read(path="src/main.py")
```

### `file_write`

Write content to a file. Parent directories are created if needed.

```
file_write(path="output.txt", content="Hello, world!")
```

### `agentguard_status`

Show the current server status: loaded policies, actor name, session ID,
and audit entry count.

```
agentguard_status()
```

### `agentguard_audit_query`

Query the audit log by action type, result, or actor. All filters are
AND-combined.

```
agentguard_audit_query(action="shell_execute", result="denied")
```

## Custom policies

Place YAML policy files in the directory specified by `--policy-dir`.
See the [Policy Authoring](policy-authoring.md) guide for the full
policy format.

Example policy that blocks dangerous git operations:

```yaml
name: safe-git
description: Prevent destructive git operations
rules:
  - action: shell_execute
    severity: high
    description: Block force push
    deny_patterns:
      - "git\\s+push\\s+.*--force"
      - "git\\s+push\\s+-f"
```

!!! note
    The MCP server checks both the MCP tool name (`shell_execute`) and
    the legacy action name (`shell_command`) for backward compatibility
    with policies written for the Python API.

## Audit logs

When `audit_dir` is configured, the server writes a JSONL file for each
session (`ag-<session-hex>.jsonl`). These files can be verified and
queried with the CLI:

```bash
# Verify integrity
agentguard audit verify audit-logs/ag-abc123.jsonl

# Show all entries
agentguard audit show audit-logs/ag-abc123.jsonl

# Generate compliance report
agentguard report eu-ai-act audit-logs/ag-abc123.jsonl
```

See the [Audit Logging](audit-logging.md) and
[Compliance Reports](compliance-reports.md) guides for more details.
