# AgentGuard

**Safety and audit framework for autonomous AI agents.**

AgentGuard provides runtime guardrails, action logging, policy enforcement,
and compliance reporting for AI agent systems.

## Key Features

- **Policy Engine** -- Define rules for what agents can and cannot do using
  YAML policies or Python code
- **Audit Logging** -- Structured, tamper-evident, hash-chained action logs
  in JSONL format
- **Runtime Guardrails** -- Validate actions before execution with
  configurable interceptors
- **Compliance Reports** -- Generate EU AI Act compliance reports from
  audit data
- **MCP Server** -- Transparent policy enforcement via Model Context Protocol
- **CLI Tool** -- Command-line access to all core capabilities

## Design Principles

1. **Framework-agnostic** -- Works with any agent framework or custom agents
2. **Zero-dependency core** -- Core library requires only PyYAML
3. **Pluggable policies** -- YAML or Python policy definitions
4. **Immutable audit logs** -- Append-only, hash-chained for integrity
5. **Type-safe** -- Full mypy strict compliance

## Quick Example

```python
from agentguard import Guard

guard = Guard()
guard.load_policy_file("policies/no-force-push.yaml")

decision = guard.check("shell_command", command="git push --force")
if not decision.allowed:
    print(f"Blocked: {decision.reason}")
```

## Getting Started

- [Installation](getting-started/installation.md) -- Install AgentGuard
- [Quick Start](getting-started/quickstart.md) -- First steps with policies and auditing

## Guides

- [Policy Authoring](guides/policy-authoring.md) -- Write custom policies
- [Audit Logging](guides/audit-logging.md) -- Record and verify agent actions
- [Runtime Guardrails](guides/runtime-guardrails.md) -- Wrap execution with safety checks
- [Compliance Reports](guides/compliance-reports.md) -- Generate EU AI Act reports
- [MCP Integration](guides/mcp-integration.md) -- Use with Claude Desktop and other MCP clients
- [CLI Reference](guides/cli-reference.md) -- Command-line tool usage

## License

AgentGuard is licensed under [AGPL-3.0-or-later](https://www.gnu.org/licenses/agpl-3.0.html).
