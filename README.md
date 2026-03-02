# AgentGuard

**Safety and audit framework for autonomous AI agents.**

[![CI](https://github.com/Roboter-Schlafen-Nicht/agentguard/actions/workflows/ci.yml/badge.svg)](https://github.com/Roboter-Schlafen-Nicht/agentguard/actions/workflows/ci.yml)
[![License: AGPL v3+](https://img.shields.io/badge/License-AGPL_v3%2B-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)

---

## The Problem

AI agents are gaining autonomy. They write code, execute shell
commands, manage infrastructure, and make decisions. But there's no
standard way to:

- **Prevent dangerous actions** before they happen
- **Log what agents actually did** in an auditable, tamper-evident way
- **Enforce policies** about what agents are allowed to do
- **Generate compliance reports** for regulatory frameworks like the
  EU AI Act

AgentGuard fills this gap.

## What AgentGuard Does

AgentGuard is a Python library that wraps around any AI agent -- whether
built with LangChain, CrewAI, AutoGen, or custom code -- and provides:

### Policy Engine

Define rules for what agents can and cannot do, in YAML or Python:

```yaml
# policies/no-destructive-git.yaml
name: no-destructive-git
description: Prevent agents from running destructive git commands
rules:
  - action: shell_command
    deny:
      - pattern: "git push --force"
      - pattern: "git reset --hard"
      - pattern: "git branch -D"
    severity: critical
```

### Audit Logging

Every agent action is logged in a structured, hash-chained format
that's tamper-evident:

```python
from agentguard.audit import AuditLog

log = AuditLog("agent-session-001")
log.record(action="file_write", target="src/main.py", result="success")
# Each entry is hash-chained to the previous one
```

### Runtime Guardrails

Intercept agent actions before they execute and validate them against
policies:

```python
from agentguard import GuardedAgent

agent = GuardedAgent(
    agent=my_langchain_agent,
    policies=["no-destructive-git", "no-secret-exposure"],
)
# Actions that violate policies are blocked before execution
```

### Compliance Reporting

Generate audit reports aligned with regulatory frameworks:

```python
from agentguard.compliance import EUAIActReportGenerator, render_json, render_text

generator = EUAIActReportGenerator()
report = generator.generate(audit_log)

# Render as JSON or plain text
print(render_json(report))
print(render_text(report))

# Or write to file
render_json(report, output="compliance-report.json")
render_text(report, output="compliance-report.txt")
```

## Installation

```bash
pip install agentguard
```

## Quick Start

```python
from agentguard import Guard
from agentguard.policies import DenyPattern

# Create a guard with a simple policy
guard = Guard()
guard.add_policy(DenyPattern(
    name="no-force-push",
    pattern=r"git push.*--force",
    severity="critical",
))

# Check an action
result = guard.check("shell_command", command="git push --force origin main")
assert result.denied
assert result.reason == "Blocked by policy: no-force-push"
```

## Architecture

```
agentguard/
  policies/       -- Policy engine: define rules for agent behavior
  audit/          -- Audit logging: structured, tamper-evident logs
  guardrails/     -- Runtime interceptors: validate before execution
  compliance/     -- Report generators: EU AI Act, SOC2, custom
  integrations/   -- Framework adapters: LangChain, CrewAI, AutoGen
```

### Design Principles

1. **Framework-agnostic** -- Works with any agent framework or custom
   agents
2. **Zero-dependency core** -- Core library has no external
   dependencies; integrations are optional extras
3. **Pluggable policies** -- YAML or Python policy definitions
4. **Immutable audit logs** -- Append-only, hash-chained for integrity
5. **Type-safe** -- Full mypy strict compliance
6. **Tested** -- TDD, high coverage, CI on every PR

## Roadmap

- [x] Project scaffolding, CI, packaging
- [x] Core policy engine (YAML + Python policies)
- [x] Audit log with hash-chaining
- [x] Runtime guardrail interceptor
- [x] EU AI Act compliance report generator
- [x] OpenClaw integration (`@agentguard/openclaw` TypeScript plugin)
- [ ] LangChain / CrewAI / AutoGen integrations
- [ ] CLI tool for policy management
- [ ] Documentation site

## Why This Exists

As AI agents become more autonomous, the question shifts from "can they
do this?" to "should they do this?" AgentGuard provides the safety
infrastructure that bridges this gap.

This project is developed by
[Roboter Schlafen Nicht](https://github.com/Roboter-Schlafen-Nicht),
an autonomous engineering consultancy. We build AI agents for
production use and needed this tool ourselves.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

AGPL-3.0-or-later. See [LICENSE](LICENSE) for details.
