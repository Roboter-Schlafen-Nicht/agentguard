# CLI Reference

AgentGuard provides a command-line interface for policy checking, audit
log inspection, and compliance reporting. The CLI uses only Python's
stdlib `argparse` — no external dependencies.

## Installation

The CLI is installed automatically with AgentGuard:

```bash
pip install agentguard
```

After installation, the `agentguard` command is available:

```bash
agentguard --version
```

## Commands

### `agentguard version`

Print the installed AgentGuard version.

```bash
agentguard version
# or
agentguard --version
```

---

### `agentguard policies list`

List all available built-in policies.

```bash
agentguard policies list
```

Output:

```
Built-in policies:
  - no-data-deletion
  - no-force-push
  - no-secret-exposure
```

### `agentguard policies show <name>`

Show the details of a built-in policy, including its rules, severity
levels, and deny patterns.

```bash
agentguard policies show no-force-push
```

Output:

```
Policy: no-force-push
Description: Prevents destructive git force-push operations
Rules (1):
  1. action: shell_command
     severity: high
     description: Block git push --force and -f flags
     deny patterns: ['git\\s+push\\s+.*--force', 'git\\s+push\\s+-f\\b']
```

---

### `agentguard check`

Check an action against loaded policies. Returns exit code 0 if allowed,
1 if denied, 2 on usage errors.

```bash
agentguard check [OPTIONS] ACTION_KIND [PARAMS...]
```

**Arguments:**

| Argument | Description |
|---|---|
| `ACTION_KIND` | The action kind to check (e.g. `shell_command`, `file_write`). |
| `PARAMS` | Action parameters as `key=value` pairs. |

**Options:**

| Option | Description |
|---|---|
| `--builtins` | Load all built-in policies. |
| `--policy PATH` | Path to a policy YAML file (repeatable). |
| `--policy-dir DIR` | Directory containing policy YAML files. |
| `--format {text,json}` | Output format (default: `text`). |

**Examples:**

```bash
# Check against built-in policies
agentguard check --builtins shell_command command="git push --force"

# Check against a custom policy file
agentguard check --policy my-policy.yaml file_write path="/etc/passwd"

# Check against all policies in a directory
agentguard check --policy-dir ./policies shell_command command="rm -rf /"

# JSON output
agentguard check --builtins --format json shell_command command="ls -la"
```

**Text output (denied):**

```
DENIED: Action 'shell_command' was denied.
  Policy: no-force-push
  Reason: Matches deny pattern: git\s+push\s+.*--force
  Severity: high
```

**JSON output (allowed):**

```json
{
  "allowed": true
}
```

---

### `agentguard audit verify`

Verify the integrity of an audit log's hash chain. Returns exit code 0
if valid, 1 if tampered.

```bash
agentguard audit verify FILE [--session ID]
```

| Option | Description |
|---|---|
| `--session ID` | Session ID for the log (default: `unknown`). |

```bash
agentguard audit verify audit.jsonl --session session-001
```

### `agentguard audit show`

Display all entries in an audit log.

```bash
agentguard audit show FILE [--session ID] [--format {text,json}]
```

| Option | Description |
|---|---|
| `--session ID` | Session ID for the log (default: `unknown`). |
| `--format {text,json}` | Output format (default: `text`). |

```bash
agentguard audit show audit.jsonl --format json
```

### `agentguard audit query`

Query audit log entries with filters. All filters are AND-combined.

```bash
agentguard audit query FILE [OPTIONS]
```

| Option | Description |
|---|---|
| `--session ID` | Session ID for the log (default: `unknown`). |
| `--action TYPE` | Filter by action type (e.g. `shell_command`). |
| `--actor NAME` | Filter by actor name. |
| `--result RESULT` | Filter by result (e.g. `allowed`, `denied`). |
| `--format {text,json}` | Output format (default: `text`). |

```bash
# Find all denied actions
agentguard audit query audit.jsonl --result denied

# Find shell commands by a specific actor
agentguard audit query audit.jsonl --action shell_command --actor coding-agent
```

---

### `agentguard report`

Generate a compliance report from an audit log.

```bash
agentguard report FRAMEWORK FILE [OPTIONS]
```

**Arguments:**

| Argument | Description |
|---|---|
| `FRAMEWORK` | Compliance framework. Currently supported: `eu-ai-act`. |
| `FILE` | Path to the audit JSONL file. |

**Options:**

| Option | Description |
|---|---|
| `--session ID` | Session ID for the log (default: `unknown`). |
| `--format {text,json}` | Output format (default: `text`). |
| `--output PATH` | Write report to a file instead of stdout. |

```bash
# Text report to stdout
agentguard report eu-ai-act audit.jsonl --session session-001

# JSON report to file
agentguard report eu-ai-act audit.jsonl --format json --output report.json
```

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Success (action allowed, log valid, report generated). |
| `1` | Failure (action denied, log tampered, error). |
| `2` | Usage error (missing arguments, invalid parameters). |
