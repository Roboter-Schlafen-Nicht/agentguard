# Quick Start

This guide walks through the core AgentGuard workflow: define policies,
check actions, log results, and generate compliance reports.

## 1. Check actions against policies

The `Guard` class is the central policy enforcement point. Load policies
from YAML files or use the built-in policies:

```python
from agentguard import Guard

guard = Guard()

# Load built-in policies
from agentguard.policies.builtins import load_all_builtins
for policy in load_all_builtins():
    guard.add_policy(policy)

# Check if an action is allowed
decision = guard.check("shell_command", command="ls -la")
print(decision.allowed)  # True

decision = guard.check("shell_command", command="git push --force")
print(decision.allowed)  # False
print(decision.reason)   # "Matches deny pattern: --force"
```

## 2. Record actions in an audit log

The `AuditLog` creates tamper-evident, hash-chained records of all
agent actions:

```python
from agentguard import AuditLog

log = AuditLog("session-001")

log.record(
    action="shell_command",
    actor="coding-agent",
    target="ls -la",
    result="allowed",
)

log.record(
    action="file_write",
    actor="coding-agent",
    target="/tmp/output.txt",
    result="allowed",
)

# Save to disk as JSONL
log.save("audit.jsonl")

# Later: verify integrity
log = AuditLog.load("audit.jsonl", "session-001")
assert log.verify()  # True if untampered
```

## 3. Use the Guardrail for combined enforcement

The `Guardrail` combines policy checking, execution, and audit logging
into a single workflow:

```python
from agentguard import Guard, AuditLog, Guardrail

guard = Guard()
guard.load_policy_file("policies/no-force-push.yaml")
log = AuditLog("session-001")

guardrail = Guardrail(guard=guard, audit_log=log, actor="my-agent")

# Execute with safety checks
result = guardrail.execute(
    action_kind="shell_command",
    target="ls -la",
    executor=lambda: "file1.txt\nfile2.txt",
    command="ls -la",
)

print(result.allowed)  # True
print(result.output)   # "file1.txt\nfile2.txt"
```

## 4. Generate compliance reports

Generate EU AI Act compliance reports from audit data:

```python
from agentguard import AuditLog
from agentguard.compliance import EUAIActReportGenerator, render_text

log = AuditLog.load("audit.jsonl", "session-001")
generator = EUAIActReportGenerator()
report = generator.generate(log)

print(render_text(report))
```

## 5. Use the CLI

AgentGuard includes a command-line tool:

```bash
# Check an action against built-in policies
agentguard check --builtins shell_command command="git push --force"

# Verify an audit log
agentguard audit verify audit.jsonl --session session-001

# Generate a compliance report
agentguard report eu-ai-act audit.jsonl --session session-001

# List built-in policies
agentguard policies list
```

## Next steps

- [Policy Authoring](../guides/policy-authoring.md) -- Write custom policies
- [Audit Logging](../guides/audit-logging.md) -- Advanced audit log usage
- [MCP Integration](../guides/mcp-integration.md) -- Use with Claude Desktop
