# Guardrails API Reference

Runtime interceptors that combine policy checking, action execution,
and audit logging into a single pipeline.

## Package exports

```python
from agentguard.guardrails import (
    ActionResult, ExecutionResult, Guardrail, Interceptor,
)
```

## Guardrail

The main runtime safety layer. Checks policies before executing actions
and records everything in the audit log.

::: agentguard.guardrails.guardrail.Guardrail
    options:
      show_source: true
      members_order: source

## ExecutionResult

The result of a guarded action execution.

::: agentguard.guardrails.guardrail.ExecutionResult
    options:
      show_source: true

## ActionResult

The result of executing an agent action via an interceptor.

::: agentguard.guardrails.models.ActionResult
    options:
      show_source: true

## Interceptor

Protocol for action executors.

::: agentguard.guardrails.models.Interceptor
    options:
      show_source: true
