# AgentGuard

**Safety guardrails for autonomous AI agents. Drop-in MCP server that
enforces policies and logs every action — the agent never even knows
it's being guarded.**

[![CI](https://github.com/Roboter-Schlafen-Nicht/agentguard/actions/workflows/ci.yml/badge.svg)](https://github.com/Roboter-Schlafen-Nicht/agentguard/actions/workflows/ci.yml)
[![License: AGPL v3+](https://img.shields.io/badge/License-AGPL_v3%2B-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)

---

## The Problem

AI coding agents run shell commands, read your secrets, and write to
production files. Today there is **nothing between the LLM and your
system** except trust.

That trust is misplaced:

- Prompt injections can make an agent `rm -rf /` or `git push --force`
- A hallucinating model can overwrite `.env` with garbage
- There is no audit trail of what the agent actually did
- Compliance teams have no evidence that AI actions were supervised

## The Solution: Transparent Proxy via MCP

AgentGuard is an **MCP server** that sits between any AI agent and your
system. It exposes the same tools the agent expects (`shell_execute`,
`file_read`, `file_write`) but enforces your policies before every
action and logs every operation in a tamper-evident audit chain.

**The agent doesn't know it's being guarded.** Zero prompt engineering.
Zero cooperation required from the LLM. It just works.

```
┌──────────────┐     MCP      ┌──────────────┐     actual
│   AI Agent   │ ──────────── │  AgentGuard  │ ──────────── System
│ (any client) │   tools      │  MCP Server  │   execution
└──────────────┘              └──────────────┘
                               │ policy check │
                               │ audit log    │
                               │ deny/allow   │
```

Works with **any MCP client**: Claude Desktop, Cursor, Windsurf,
VS Code Copilot, OpenCode, Cline, Zed, and custom agents.

## Quick Start

### 1. Install

```bash
pip install agentguard[mcp]
```

### 2. Write a policy

```yaml
# policies/safety.yaml
name: prevent-disasters
description: Block destructive operations
rules:
  - action: shell_execute
    deny:
      - pattern: "git push.*--force"
      - pattern: "git reset --hard"
      - pattern: "rm -rf /"
    severity: critical

  - action: file_write
    deny:
      - pattern: '\.env$'
      - pattern: 'credentials'
    severity: critical
```

### 3. Point your MCP client at AgentGuard

```python
from agentguard.mcp.server import create_server

app = create_server(
    policy_dir="policies/",
    audit_dir="audit_logs/",
    load_builtins=True,      # includes sensible defaults
)
app.run()                     # stdio transport
```

Or configure in your MCP client's settings (e.g. Claude Desktop):

```json
{
  "mcpServers": {
    "agentguard": {
      "command": "python",
      "args": [
        "-c",
        "from agentguard.mcp.server import create_server; create_server(policy_dir='policies/', audit_dir='audit_logs/', load_builtins=True).run()"
      ]
    }
  }
}
```

That's it. Every `shell_execute`, `file_read`, and `file_write` call
from your agent now passes through AgentGuard's policy engine. Denied
actions never execute. Everything is logged.

## What You Get

### Policy Engine — define what agents can and cannot do

YAML policies with regex-based deny patterns. Severity levels from
`low` to `critical`. Built-in policies for common dangers (force push,
secret exposure, data deletion). Fully extensible:

```python
from agentguard import Guard

guard = Guard()
guard.load_policy_file("policies/safety.yaml")

result = guard.check("shell_execute", command="git push --force origin main")
assert result.denied
# "Blocked by policy: prevent-disasters"
```

### Audit Log — tamper-evident record of every agent action

Every action is recorded in a hash-chained JSONL log. Each entry
links to the previous via SHA-256. If anyone tampers with a single
entry, the chain breaks:

```python
from agentguard.audit import AuditLog

log = AuditLog("session-001")
log.record(action="shell_execute", actor="agent-001", target="ls -la", result="allowed")
log.save("audit/session-001.jsonl")

# Verify integrity
assert log.verify()  # True — chain is intact
```

### Runtime Guardrails — intercept before execution

The `Guardrail` class composes policy checking, execution, and audit
logging into a single call:

```python
from agentguard import Guardrail, Guard
from agentguard.audit import AuditLog
from agentguard.guardrails import ActionResult

guard = Guard()
audit = AuditLog("session")

def my_interceptor(action_kind: str, **params: str) -> ActionResult:
    """Execute the action and return a result."""
    return ActionResult(action_kind=action_kind, params=params, executed=True, output="hello")

guardrail = Guardrail(guard=guard, interceptor=my_interceptor, audit_log=audit)

result = guardrail.execute("shell_execute", command="echo hello")
# result.decision.allowed, result.action_result.output
```

### EU AI Act Compliance Reports

Generate structured compliance reports from audit logs:

```python
from agentguard.compliance import EUAIActReportGenerator, render_json

generator = EUAIActReportGenerator()
report = generator.generate(audit)
render_json(report, output="compliance-report.json")
```

### Sidecar Tools

The MCP server also exposes `agentguard_status` (show loaded policies)
and `agentguard_audit_query` (search the audit log by action, result,
or actor) — so you can ask the agent "what policies are active?"
or "show me all denied actions by a given actor."

## Why MCP?

The [Model Context Protocol](https://modelcontextprotocol.io) is an
open standard for connecting AI agents to external tools. By
implementing AgentGuard as an MCP server:

- **Universal compatibility** — works with any MCP client, present and
  future
- **Zero agent modification** — no SDK integration, no wrapper code,
  no prompt engineering
- **Transparent enforcement** — the agent sees normal tools; policies
  are invisible
- **Decoupled deployment** — security team manages policies, dev team
  manages agents

This replaces the need for framework-specific plugins (LangChain,
CrewAI, etc.). One integration covers all agents.

## Architecture

```
src/agentguard/
  policies/       Policy engine: rules, Guard, YAML loader, builtins
  audit/          Audit logging: hash-chained entries, JSONL, verify
  guardrails/     Runtime interceptor: Guardrail, ExecutionResult
  compliance/     Report generators: EU AI Act, renderers
  mcp/            MCP server: transparent proxy with policy enforcement
```

### Design Principles

1. **Transparent** — agents don't know they're guarded
2. **Zero-trust** — no reliance on LLM cooperation or prompt adherence
3. **Auditable** — every action is hash-chained and verifiable
4. **Extensible** — YAML policies, pluggable interceptors
5. **Type-safe** — full mypy strict compliance
6. **Tested** — TDD, 95% coverage, CI on Python 3.10–3.13

## Roadmap

- [x] Core policy engine (YAML + Python policies, builtins)
- [x] Audit log with SHA-256 hash-chaining
- [x] Runtime guardrail interceptor
- [x] EU AI Act compliance report generator
- [x] MCP server with transparent policy enforcement
- [ ] CLI tool for policy management and server startup
- [ ] Documentation site
- [ ] HTTP/SSE transport for remote deployment
- [ ] Real-time alerting and dashboard

## Who This Is For

- **Engineering teams** deploying AI coding agents (Copilot, Cursor,
  Claude) who need guardrails before the agent touches production
- **Security teams** who need audit trails and policy enforcement for
  AI-assisted workflows
- **Compliance teams** who need evidence that AI actions are supervised
  and logged per EU AI Act requirements
- **Anyone** running autonomous agents who wants to sleep at night

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

AGPL-3.0-or-later. See [LICENSE](LICENSE) for details.

---

Built by [Roboter Schlafen Nicht](https://github.com/Roboter-Schlafen-Nicht) —
autonomous engineering consultancy. We build AI agents for production
and needed this tool ourselves.
