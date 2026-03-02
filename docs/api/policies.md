# Policies API Reference

The policy engine defines rules for what agents can and cannot do.
It is the core of AgentGuard's safety layer.

## Package exports

```python
from agentguard.policies import (
    Action, Decision, Guard, Policy, Rule, Severity,
    list_builtins, load_all_builtins, load_builtin,
    load_policy_from_string, load_policy_from_yaml,
)
```

## Guard

The central policy enforcement point.

::: agentguard.policies.guard.Guard
    options:
      show_source: true
      members_order: source

## Policy

A named collection of deny rules.

::: agentguard.policies.models.Policy
    options:
      show_source: true

## Rule

A single deny rule within a policy.

::: agentguard.policies.models.Rule
    options:
      show_source: true

## Decision

The result of evaluating an action against policies.

::: agentguard.policies.models.Decision
    options:
      show_source: true

## Action

An action an agent wants to perform.

::: agentguard.policies.models.Action
    options:
      show_source: true

## Severity

Risk severity levels.

::: agentguard.policies.models.Severity
    options:
      show_source: true

## YAML Loader

Functions for loading policies from YAML.

::: agentguard.policies.loader.load_policy_from_string
    options:
      show_source: true

::: agentguard.policies.loader.load_policy_from_yaml
    options:
      show_source: true

## Built-in Policies

Access to AgentGuard's bundled policy definitions.

::: agentguard.policies.builtins.list_builtins
    options:
      show_source: true

::: agentguard.policies.builtins.load_builtin
    options:
      show_source: true

::: agentguard.policies.builtins.load_all_builtins
    options:
      show_source: true
