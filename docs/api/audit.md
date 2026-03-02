# Audit API Reference

Structured, tamper-evident action logging with hash chaining and
JSONL persistence.

## Package exports

```python
from agentguard.audit import AuditEntry, AuditLog
```

## AuditLog

Hash-chained, append-only audit log.

::: agentguard.audit.log.AuditLog
    options:
      show_source: true
      members_order: source

## AuditEntry

A single entry in the audit trail.

::: agentguard.audit.models.AuditEntry
    options:
      show_source: true
      members_order: source
