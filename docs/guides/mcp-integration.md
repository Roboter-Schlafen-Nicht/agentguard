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

The MCP server exposes seven action tools (`shell_execute`, `file_read`,
`file_write`, `file_edit`, `file_glob`, `file_grep`, `file_list`) and
two introspection tools (`agentguard_status`,
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

### `file_edit`

Perform exact string replacement in a file. Rejects if the old string
is not found, matches multiple times (without `replace_all`), or is
identical to the new string.

```
file_edit(path="src/main.py", old_string="v1", new_string="v2")
file_edit(path="src/main.py", old_string="foo", new_string="bar", replace_all=True)
```

| Parameter | Type | Required | Description |
|---|---|---|---|
| `path` | `str` | Yes | File path to edit. |
| `old_string` | `str` | Yes | Exact text to find. |
| `new_string` | `str` | Yes | Replacement text. |
| `replace_all` | `bool` | No | Replace all occurrences (default: `False`). |

### `file_glob`

Search for files matching a glob pattern. Returns up to 100 results
sorted by modification time (most recent first).

```
file_glob(pattern="**/*.py")
file_glob(pattern="src/**/*.ts", path="/project")
```

| Parameter | Type | Required | Description |
|---|---|---|---|
| `pattern` | `str` | Yes | Glob pattern (e.g., `**/*.py`). |
| `path` | `str` | No | Base directory (default: current directory). |

### `file_grep`

Search file contents using regex patterns. Returns up to 100 matches
with file path, line number, and matching content.

```
file_grep(pattern="def test_", path="tests/")
file_grep(pattern="TODO", include="*.py")
```

| Parameter | Type | Required | Description |
|---|---|---|---|
| `pattern` | `str` | Yes | Regex pattern to search for. |
| `path` | `str` | No | Directory to search (default: current directory). |
| `include` | `str` | No | File filter (e.g., `*.py`, `*.{ts,tsx}`). |

### `file_list`

List directory contents. Directories are marked with a trailing `/`.
Common directories (`.git`, `node_modules`, `__pycache__`, etc.) are
excluded by default. Returns up to 100 entries.

```
file_list()
file_list(path="src/")
```

| Parameter | Type | Required | Description |
|---|---|---|---|
| `path` | `str` | No | Directory to list (default: current directory). |

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

## Client enforcement levels

Most MCP clients have their own native tools (shell, file read/write,
etc.) that bypass the MCP server entirely. Enforcement coverage depends
on whether the client can disable these native tools:

| Client | Full Enforcement? | Notes |
|--------|:---:|---|
| Claude Desktop | ✅ Yes | No native file/shell tools — all tools come from MCP |
| OpenCode | ✅ Yes | Deny native tools via `opencode.json` config |
| Cursor, Windsurf, VS Code Copilot, Cline, Zed | ⚠️ Partial | Native tools bypass AgentGuard |

### OpenCode configuration

To achieve full enforcement with OpenCode, deny native tools so all
operations route through AgentGuard's MCP tools:

```json
{
  "permission": {
    "bash": "deny",
    "read": "deny",
    "edit": "deny",
    "write": "deny",
    "glob": "deny",
    "grep": "deny"
  }
}
```

MCP tools (prefixed with `agentguard_` by OpenCode) are unaffected by
these denials.

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
