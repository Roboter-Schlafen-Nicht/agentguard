# Runtime Guardrails

The `Guardrail` class combines policy checking, execution, and audit
logging into a single workflow. It validates actions before execution
and records everything to an audit log.

## Basic usage

```python
from agentguard import Guard, AuditLog, Guardrail

guard = Guard()
guard.load_policy_file("policies/no-force-push.yaml")
log = AuditLog("session-001")

guardrail = Guardrail(guard=guard, audit_log=log, actor="my-agent")
```

## Executing actions

The `execute()` method checks the action against policies, runs it if
allowed, and logs the result:

```python
result = guardrail.execute(
    action_kind="shell_command",
    target="ls -la",
    executor=lambda: "file1.txt\nfile2.txt",
    command="ls -la",
)

print(result.allowed)   # True
print(result.output)    # "file1.txt\nfile2.txt"
print(result.decision)  # The full Decision object
```

### When an action is denied

```python
result = guardrail.execute(
    action_kind="shell_command",
    target="git push --force",
    executor=lambda: None,  # Never called
    command="git push --force",
)

print(result.allowed)  # False
print(result.output)   # None -- executor was not called
```

The executor function is only called if the policy check passes.

## Custom interceptors

Interceptors let you add custom logic before or after execution.
An interceptor is any callable that takes an `ActionResult` and returns
a modified `ActionResult`:

```python
from agentguard.guardrails import ActionResult

def log_interceptor(result: ActionResult) -> ActionResult:
    """Log all actions to an external system."""
    print(f"Action: {result.action_kind} -> {result.allowed}")
    return result

guardrail = Guardrail(
    guard=guard,
    audit_log=log,
    actor="my-agent",
    interceptors=[log_interceptor],
)
```

Interceptors run after the policy check but before the executor.

## ExecutionResult

The `execute()` method returns an `ExecutionResult` with:

| Attribute | Type | Description |
|-----------|------|-------------|
| `allowed` | bool | Whether the action was permitted |
| `output` | Any | Return value of the executor (None if denied) |
| `decision` | Decision | The policy decision object |
| `action_kind` | str | The action type that was checked |
| `target` | str | The action target |

## Error handling

If the executor raises an exception, it is recorded in the audit log
with `result="error"` and the exception is re-raised:

```python
def failing_executor() -> str:
    raise RuntimeError("Something went wrong")

try:
    result = guardrail.execute(
        action_kind="shell_command",
        target="broken-command",
        executor=failing_executor,
        command="broken-command",
    )
except RuntimeError:
    pass  # Error is logged to audit before re-raising
```
