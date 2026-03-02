# Audit Logging

AgentGuard's audit system creates tamper-evident, hash-chained logs of
all agent actions. Each entry is linked to the previous one via SHA-256
hashes, making it possible to detect any tampering.

## Creating an audit log

```python
from agentguard import AuditLog

log = AuditLog("session-001")
```

The session ID groups related entries together. Use a unique ID per
agent session.

## Recording actions

```python
log.record(
    action="shell_command",
    actor="coding-agent",
    target="ls -la /tmp",
    result="allowed",
)
```

### Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `action` | str | Action type (e.g. `shell_command`, `file_write`) |
| `actor` | str | Who performed the action |
| `target` | str | What the action targeted |
| `result` | str | Outcome (e.g. `allowed`, `denied`, `error`) |

## Saving and loading

```python
# Save to JSONL file
log.save("audit.jsonl")

# Load from file
log = AuditLog.load("audit.jsonl", "session-001")
```

The JSONL format stores one JSON object per line, making it
append-friendly and easy to parse.

## Verifying integrity

```python
if log.verify():
    print("Log integrity verified")
else:
    print("WARNING: Log may have been tampered with")
```

The `verify()` method recalculates the hash chain and checks that
each entry's hash matches. Any modification to an entry will break
the chain.

## Querying entries

```python
# Filter by action type
results = log.query(action="shell_command")

# Filter by actor
results = log.query(actor="coding-agent")

# Filter by result
results = log.query(result="denied")

# Combine filters
results = log.query(action="file_write", result="allowed")
```

## Hash chain structure

Each `AuditEntry` contains:

- `timestamp` -- When the action occurred
- `action` -- The action type
- `actor` -- Who performed it
- `target` -- What was targeted
- `result` -- The outcome
- `previous_hash` -- SHA-256 hash of the previous entry
- `hash` -- SHA-256 hash of this entry (including `previous_hash`)

The first entry uses an empty string as `previous_hash`. This creates
an append-only chain where any modification invalidates all subsequent
entries.

## CLI usage

```bash
# Verify log integrity
agentguard audit verify audit.jsonl --session session-001

# Show all entries
agentguard audit show audit.jsonl --session session-001

# Query entries
agentguard audit query audit.jsonl --session session-001 --action shell_command
agentguard audit query audit.jsonl --session session-001 --result denied --format json
```
