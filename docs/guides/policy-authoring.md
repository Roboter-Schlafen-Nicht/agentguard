# Policy Authoring

Policies define what actions agents are allowed or denied. AgentGuard
supports YAML-based policy definitions with regex pattern matching.

## Policy structure

A policy YAML file has this structure:

```yaml
name: my-policy
description: Optional description of what this policy enforces
rules:
  - action: shell_command
    deny:
      - pattern: "rm -rf"
        description: Prevent recursive deletion
      - pattern: "--force"
    severity: critical
    description: Block dangerous shell commands
```

### Fields

| Field | Required | Description |
|-------|----------|-------------|
| `name` | Yes | Unique name for the policy |
| `description` | No | Human-readable description |
| `rules` | Yes | List of rules to enforce |

### Rule fields

| Field | Required | Description |
|-------|----------|-------------|
| `action` | Yes | Action kind to match (e.g. `shell_command`, `file_write`) |
| `deny` | Yes | List of deny patterns |
| `severity` | No | `low`, `medium`, `high`, or `critical` (default: `medium`) |
| `description` | No | Human-readable rule description |

### Deny pattern fields

Each deny pattern can be a string (shorthand) or an object:

```yaml
# Shorthand -- just the regex pattern
deny:
  - pattern: "rm -rf"

# With description
deny:
  - pattern: "rm -rf"
    description: Prevent recursive force deletion
```

## Built-in policies

AgentGuard ships with three built-in policies:

| Policy | Description |
|--------|-------------|
| `no-force-push` | Blocks `git push --force` and similar |
| `no-secret-exposure` | Blocks commands that may expose secrets |
| `no-data-deletion` | Blocks destructive deletion commands |

Use them in Python:

```python
from agentguard.policies.builtins import load_builtin, load_all_builtins

# Load one
policy = load_builtin("no-force-push")

# Load all
policies = load_all_builtins()
```

Or via CLI:

```bash
agentguard policies list
agentguard policies show no-force-push
```

## Loading policies

### From YAML files

```python
from agentguard import Guard

guard = Guard()
guard.load_policy_file("path/to/policy.yaml")
```

### From a directory

```python
from pathlib import Path

guard = Guard()
for yaml_file in Path("policies/").glob("*.yaml"):
    guard.load_policy_file(yaml_file)
```

### From YAML strings

```python
from agentguard.policies.loader import load_policy_from_string

policy = load_policy_from_string("""
name: inline-policy
rules:
  - action: file_write
    deny:
      - pattern: "/etc/"
    severity: high
""")
```

## How matching works

When `guard.check()` is called, the Guard evaluates all loaded policies:

1. Each rule's `action` field is compared to the `action_kind` argument
2. If matched, each deny pattern's `pattern` is tested as a regex
   against all parameter values
3. If any pattern matches, the action is denied
4. If no rules deny the action, it is allowed

```python
decision = guard.check("shell_command", command="git push --force origin main")

# decision.allowed == False
# decision.denied_by == "no-force-push"
# decision.reason == "Matches deny pattern: --force"
# decision.severity == Severity.CRITICAL
```
