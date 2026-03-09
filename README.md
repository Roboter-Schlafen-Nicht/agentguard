# AgentGuard

**Safety guardrails for autonomous AI agents. Policy enforcement, tamper-evident
audit logging, and LLM API filtering — the agent never even knows it's being
guarded.**

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
- Secrets and PII leak into LLM prompts — sent to third-party APIs
- LLM responses can contain injected instructions or exfiltration attempts
- There is no audit trail of what the agent actually did
- Compliance teams have no evidence that AI actions were supervised

## The Solution

AgentGuard guards AI agents at **two layers**:

1. **MCP Server** — sits between the agent and your OS. Intercepts every
   `shell_execute`, `file_read`, and `file_write` call. Enforces policies
   before execution. Works with any MCP client.

2. **LLM API Proxy** — sits between the agent and the LLM API. Scans
   outbound prompts for secrets/PII before they reach the LLM. Scans
   inbound responses for prompt injection and exfiltration patterns in
   real time, including streaming (SSE). Terminates dangerous streams
   mid-flight.

<p align="center">
  <img src="docs/architecture.svg" alt="AgentGuard architecture diagram" width="800">
</p>

**The agent doesn't know it's being guarded.** Zero prompt engineering.
Zero cooperation required from the LLM.

## Quick Start

### MCP Server — guard tool calls

Install and point your MCP client at AgentGuard:

```bash
pip install agentguard[mcp]
```

```json
{
  "mcpServers": {
    "agentguard": {
      "command": "python",
      "args": ["-m", "agentguard", "serve", "--builtins", "--audit-dir", "audit/"]
    }
  }
}
```

Every `shell_execute`, `file_read`, and `file_write` call now passes
through AgentGuard. Denied actions never execute. Everything is logged.

Works with **any MCP client**: Claude Desktop, Cursor, Windsurf,
VS Code Copilot, OpenCode, Cline, Zed, and custom agents.

### LLM API Proxy — guard prompts and responses

```bash
pip install agentguard[proxy]
```

```bash
agentguard proxy https://api.openai.com \
  --builtins \
  --scan-responses \
  --audit-dir audit/ \
  --port 8080
```

Point your agent's API base URL at `http://localhost:8080` instead of
`https://api.openai.com`. AgentGuard forwards requests transparently,
scanning for policy violations in both directions:

- **Outbound** — blocks secrets, API keys, PII, and internal paths
  from leaking into prompts
- **Inbound** — scans streaming responses for prompt injection,
  persona hijacking, and data exfiltration patterns. Terminates the
  SSE stream and injects a warning when a violation is detected

Compatible with OpenAI, Azure OpenAI, GitHub Copilot, and any
OpenAI-compatible API (LiteLLM, vLLM, Ollama, etc.) via the built-in
provider adapter.

## Features

### Policy Engine

YAML policies with regex-based deny patterns. Separate action kinds
for tool calls (`shell_execute`, `file_read`, `file_write`) and LLM
traffic (`llm_request`, `llm_response`). Optional `scan` field targets
specific parts of LLM messages (`messages`, `system`, `content`, `all`).

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

```python
from agentguard import Guard

guard = Guard()
guard.load_policy_file("policies/safety.yaml")

result = guard.check("shell_execute", command="git push --force origin main")
assert result.denied
# "Blocked by policy: prevent-disasters"
```

### 11 Built-in Policies

Ship with sensible defaults — load with `--builtins`:

| Policy | Layer | What it blocks |
|--------|-------|----------------|
| `no-force-push` | Tool | `git push --force`, `git reset --hard` |
| `no-data-deletion` | Tool | `rm -rf /`, `DROP TABLE`, `DELETE FROM` |
| `no-secret-exposure` | Tool | Reading `.env`, credentials, key files |
| `no-env-commit` | Tool | Committing `.env` or credential files |
| `no-hook-bypass` | Tool | `--no-verify`, `--no-gpg-sign` |
| `no-secret-in-prompt` | Proxy | API keys, tokens, passwords in prompts |
| `no-pii-leak` | Proxy | Email addresses, SSNs, phone numbers in prompts |
| `no-internal-paths` | Proxy | Internal hostnames, IPs, infrastructure paths |
| `no-prompt-injection` | Proxy | "Ignore previous instructions" and variants |
| `no-persona-jailbreak` | Proxy | DAN, persona override, system prompt injection |
| `detect-drift-triggers` | Proxy | Meta-reflective prompts, emotional manipulation, grandiose responses |

### Tamper-Evident Audit Log

Every action is recorded in a hash-chained JSONL log. Each entry links
to the previous via SHA-256 — if anyone tampers with a single entry,
the chain breaks:

```python
from agentguard.audit import AuditLog

log = AuditLog("session-001")
log.record(action="shell_execute", actor="agent-001", target="ls -la", result="allowed")
log.save("audit/session-001.jsonl")

assert log.verify()  # True — chain is intact
```

### Runtime Guardrails

The `Guardrail` class composes policy checking, execution, and audit
logging into a single call:

```python
from agentguard import Guardrail, Guard
from agentguard.audit import AuditLog
from agentguard.guardrails import ActionResult

guard = Guard()
audit = AuditLog("session")

def my_interceptor(action_kind: str, **params: str) -> ActionResult:
    return ActionResult(action_kind=action_kind, params=params, executed=True, output="ok")

guardrail = Guardrail(guard=guard, interceptor=my_interceptor, audit_log=audit)
result = guardrail.execute("shell_execute", command="echo hello")
```

### EU AI Act Compliance Reports

Generate structured compliance reports from audit data, mapping to
Art. 9 (Risk Management), Art. 12 (Record-keeping), Art. 13
(Transparency), and Art. 14 (Human Oversight):

```python
from agentguard.compliance import EUAIActReportGenerator, render_json

generator = EUAIActReportGenerator()
report = generator.generate(audit)
render_json(report, output="compliance-report.json")
```

```bash
agentguard report eu-ai-act audit/session.jsonl --format json --output report.json
```

### Outbound Scanner

Programmatic detection of sensitive content in text, independent of
the policy engine. 18 regex patterns across 3 categories:

```python
from agentguard.proxy.outbound import scan_text, FindingCategory

findings = scan_text("My API key is sk-abc123xyz")
# [Finding(category=SECRET, name="openai_api_key", ...)]
```

### Inbound Scanner (Streaming)

Streaming-aware response scanner with a sliding window. Feeds SSE
chunks incrementally, runs policy checks against the accumulated
content, and signals denial mid-stream:

```python
from agentguard.proxy.inbound import InboundScanner

scanner = InboundScanner(guard)
for chunk in sse_stream:
    result = scanner.feed(chunk)
    if result is not None:
        # Policy violation detected — terminate stream
        break
summary = scanner.finalize()
```

### Provider Adapters

Pluggable format adapters for different LLM APIs. The `Provider`
protocol defines request/response parsing and streaming content
extraction. Ships with an OpenAI adapter; auto-detected or set
explicitly:

```python
from agentguard.proxy.providers import get_provider, list_providers

provider = get_provider("openai")
params = provider.extract_request_params(body)
content = provider.extract_stream_content(sse_data)
```

### MCP Sidecar Tools

The MCP server exposes `agentguard_status` (loaded policies and
session info) and `agentguard_audit_query` (search audit by action,
result, or actor) — so you can ask the agent "what policies are
active?" or "show me all denied actions."

## CLI

```
agentguard version                          Print version
agentguard policies [--dir DIR] [--builtins] List loaded policies
agentguard check ACTION [--params K=V ...]  Test an action against policies
agentguard audit verify FILE                Verify audit log integrity
agentguard audit query FILE [--action ...]  Query audit entries
agentguard report FRAMEWORK FILE            Generate compliance report
agentguard serve [--builtins] [--audit-dir]  Start MCP server
agentguard proxy URL [--scan-responses]     Start LLM API proxy
```

## Installation

```bash
# Core policy engine + audit (no network dependencies)
pip install agentguard

# With MCP server
pip install agentguard[mcp]

# With LLM API proxy
pip install agentguard[proxy]

# Everything
pip install agentguard[mcp,proxy]
```

Requires Python 3.10+. Tested on 3.10, 3.11, 3.12, and 3.13.

## Architecture

```
src/agentguard/
  policies/         Policy engine: Rule, Guard, YAML loader, 11 built-in policies
  audit/            Audit logging: hash-chained JSONL, integrity verification
  guardrails/       Runtime interceptor: Guardrail, hooks, ActionResult
  compliance/       Report generators: EU AI Act, JSON/text renderers
  mcp/              MCP server: transparent tool proxy with policy enforcement
  proxy/            LLM API proxy: middleware, outbound/inbound scanners
    providers/      Format adapters: Provider protocol, OpenAI adapter
  cli.py            Command-line interface
```

### Design Principles

1. **Transparent** — agents don't know they're guarded
2. **Zero-trust** — no reliance on LLM cooperation or prompt adherence
3. **Auditable** — every action is hash-chained and verifiable
4. **Two-layer** — guards both tool calls (MCP) and LLM traffic (proxy)
5. **Streaming-aware** — scans SSE responses in real time, terminates on violation
6. **Extensible** — YAML policies, pluggable providers, pluggable interceptors
7. **Type-safe** — full mypy strict compliance, py.typed marker
8. **Tested** — 892 tests, TDD, CI on Python 3.10–3.13

## Roadmap

- [x] Core policy engine (YAML + Python policies, 11 built-in policies)
- [x] Audit log with SHA-256 hash-chaining and integrity verification
- [x] Runtime guardrail interceptor with pre/post hooks
- [x] EU AI Act compliance report generator (JSON + text)
- [x] MCP server with transparent policy enforcement and sidecar tools
- [x] CLI tool (`check`, `audit`, `policies`, `report`, `serve`, `proxy`)
- [x] LLM API proxy with outbound scanner (secrets, PII, internal paths)
- [x] Streaming inbound scanner (SSE sliding window, mid-stream termination)
- [x] Built-in prompt/response policies (4 proxy policies)
- [x] OpenAI-compatible provider adapter with auto-detection
- [ ] Anthropic provider adapter
- [ ] Audit log rotation, retention, and cross-session aggregation
- [ ] ISO 42001 and NIST AI RMF compliance reports
- [ ] SOC 2 audit evidence mapping
- [ ] Real-time denial notifications and dashboard integration
- [ ] Conditional policies (time-of-day, branch, environment rules)
- [x] Persona safety policies (jailbreak detection, drift monitoring)

## Who This Is For

- **Engineering teams** deploying AI coding agents (Copilot, Cursor,
  Claude) who need guardrails before the agent touches production
- **Security teams** who need audit trails and policy enforcement for
  AI-assisted workflows, including LLM API traffic filtering
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
