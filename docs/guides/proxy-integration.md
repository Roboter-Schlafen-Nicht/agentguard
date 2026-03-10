# LLM API Proxy Integration Guide

This guide covers integrating the AgentGuard LLM API proxy with AI
coding tools. The proxy sits between your AI tool and the LLM API,
scanning outbound prompts for secrets/PII and inbound responses for
prompt injection — transparently, without any cooperation from the LLM.

## Architecture

```
┌─────────────┐     ┌──────────────────────┐     ┌──────────────────┐
│  AI Tool     │────▶│  AgentGuard Proxy     │────▶│  LLM API         │
│  (OpenCode,  │◀────│  (localhost:8080)      │◀────│  (Copilot, OpenAI│
│   Cursor...) │     │                        │     │   Anthropic...)   │
└─────────────┘     │  ✓ Outbound scanning   │     └──────────────────┘
                     │  ✓ Inbound scanning    │
                     │  ✓ Policy enforcement  │
                     │  ✓ Audit logging       │
                     └──────────────────────┘
```

**What the proxy catches:**

| Direction | Threat | Example |
|-----------|--------|---------|
| Outbound  | Secret leakage | API keys, tokens, passwords in prompts |
| Outbound  | PII leakage | Email addresses, SSNs, phone numbers |
| Outbound  | Internal paths | File system paths, private IPs |
| Outbound  | Prompt injection | "Ignore previous instructions" |
| Inbound   | Response injection | Exfiltration URLs, hidden instructions |
| Inbound   | Persona hijacking | DAN-style jailbreak responses |
| Inbound   | Drift triggers | Emotional manipulation, grandiose claims |

## Prerequisites

```bash
pip install agentguard[proxy]
```

## Quick Start

### 1. Start the proxy

```bash
# Default: all built-in policies, response scanning enabled
agentguard proxy https://api.githubcopilot.com \
  --builtins --scan-responses --audit-dir audit/ --port 8080
```

Or use the daemon management script:

```bash
# Start as background daemon with health checks
bash scripts/proxy.sh start

# Check status
bash scripts/proxy.sh status

# Stop
bash scripts/proxy.sh stop
```

### 2. Point your AI tool at the proxy

Instead of connecting directly to the LLM API, configure your tool to
use `http://127.0.0.1:8080` as its API base URL. The proxy forwards
all requests transparently, including authentication headers.

---

## OpenCode (Full Enforcement)

OpenCode achieves **full two-layer enforcement** with AgentGuard:

- **Layer 1 (MCP):** Tool calls go through the AgentGuard MCP server
- **Layer 2 (Proxy):** LLM API calls go through the AgentGuard proxy

### Setup

**Step 1:** Start the proxy before launching OpenCode:

```bash
bash scripts/proxy.sh start
```

**Step 2:** Add the proxy endpoint to your `opencode.json`:

```json
{
  "model": "github-copilot/claude-opus-4.6",
  "provider": {
    "github-copilot": {
      "options": {
        "baseURL": "http://127.0.0.1:8080"
      }
    }
  },
  "mcp": {
    "agentguard": {
      "type": "local",
      "command": ["agentguard", "serve", "--builtins", "--auto-discover", "--audit-dir", "private/audit"]
    }
  },
  "permission": {
    "*": "allow",
    "bash": "deny",
    "read": "deny",
    "write": "deny",
    "edit": "deny",
    "glob": "deny",
    "grep": "deny"
  }
}
```

This gives you:

- ✅ All tool calls (shell, file read/write/edit/glob/grep) enforced via MCP
- ✅ All LLM prompts scanned for secrets, PII, and injection attacks
- ✅ All LLM responses scanned for prompt injection and exfiltration
- ✅ Full audit trail for both layers

### Upstream URLs by provider

| Provider | Upstream URL |
|----------|-------------|
| GitHub Copilot | `https://api.githubcopilot.com` |
| OpenAI | `https://api.openai.com` |
| Anthropic | `https://api.anthropic.com` |
| Azure OpenAI | `https://{resource}.openai.azure.com` |
| Ollama (local) | `http://localhost:11434` |

For providers other than GitHub Copilot, update both the proxy
upstream URL and the `baseURL` in `opencode.json`:

```bash
# For direct OpenAI
bash scripts/proxy.sh start --upstream https://api.openai.com
```

```json
{
  "provider": {
    "openai": {
      "options": {
        "baseURL": "http://127.0.0.1:8080"
      }
    }
  }
}
```

---

## Claude Desktop

Claude Desktop uses the Anthropic API. Configure it by setting the
`ANTHROPIC_BASE_URL` environment variable before launching:

```bash
# Start the proxy targeting Anthropic
agentguard proxy https://api.anthropic.com \
  --builtins --scan-responses --audit-dir audit/ --port 8080

# Launch Claude Desktop with proxy
ANTHROPIC_BASE_URL=http://127.0.0.1:8080 open -a "Claude"
```

> **Note:** Full Anthropic message format support requires the
> Anthropic provider adapter (coming soon). Basic support works via
> the built-in fallback parser.

---

## Cursor

Cursor supports custom API endpoints in its settings:

1. Start the proxy: `bash scripts/proxy.sh start`
2. Open Cursor Settings → Models → OpenAI API Base URL
3. Set to `http://127.0.0.1:8080`
4. Or set the environment variable:
   ```bash
   OPENAI_BASE_URL=http://127.0.0.1:8080 cursor .
   ```

---

## Cline (VS Code Extension)

Cline allows custom API base URLs in its extension settings:

1. Start the proxy: `bash scripts/proxy.sh start`
2. Open VS Code Settings → Cline → API Base URL
3. Set to `http://127.0.0.1:8080`

---

## VS Code Copilot

VS Code Copilot routes through GitHub's infrastructure. Use the
system-level proxy setting:

1. Start the proxy on the appropriate port
2. In VS Code settings: `"http.proxy": "http://127.0.0.1:8080"`
3. Or set the `HTTPS_PROXY` environment variable

> **Note:** This routes ALL VS Code HTTP traffic through the proxy,
> not just LLM calls. Use with caution.

---

## Windsurf / Zed

For tools that support OpenAI-compatible endpoints:

1. Start the proxy with the appropriate upstream
2. Configure the tool's API endpoint to `http://127.0.0.1:8080`
3. Authentication headers pass through transparently

---

## Protection Presets

The proxy supports three protection levels:

| Preset | Policies | Best for |
|--------|:---:|---------|
| `permissive` | 3 | Development — blocks only catastrophic actions |
| `balanced` | 8 | Default — covers tools and basic LLM filtering |
| `strict` | 11 | Production — includes drift detection and persona safety |

```bash
# Use a preset
bash scripts/proxy.sh start --preset balanced

# Or load all built-in policies (equivalent to strict + tool policies)
bash scripts/proxy.sh start --builtins
```

---

## Daemon Management

The `scripts/proxy.sh` script manages the proxy lifecycle:

```bash
# Start with defaults (GitHub Copilot, all policies, response scanning)
bash scripts/proxy.sh start

# Start with custom settings
bash scripts/proxy.sh start \
  --upstream https://api.openai.com \
  --port 9090 \
  --preset balanced \
  --audit-dir ./my-audit/

# Check status and loaded policies
bash scripts/proxy.sh status

# Quick health check (for CI/scripts — exits 0 if healthy)
bash scripts/proxy.sh health

# Stop the daemon
bash scripts/proxy.sh stop
```

### Environment variables

Override defaults without CLI flags:

| Variable | Default | Description |
|----------|---------|-------------|
| `AGENTGUARD_PROXY_UPSTREAM` | `https://api.githubcopilot.com` | Upstream LLM API |
| `AGENTGUARD_PROXY_PORT` | `8080` | Proxy listen port |
| `AGENTGUARD_PROXY_PRESET` | (none) | Protection preset |
| `AGENTGUARD_PROXY_AUDIT_DIR` | `./private/audit/proxy` | Audit log directory |

---

## Systemd User Service (Auto-Start)

For production use, install the proxy as a systemd user service so it
starts automatically on login and restarts on crash:

### Install

```bash
bash scripts/proxy-install.sh install [preset]
```

This will:

1. Resolve the full path to the `agentguard` binary
2. Copy the service template to `~/.config/systemd/user/`
3. Create a default config at `~/.config/agentguard/proxy.env`
4. Enable and start the service

The default preset is `builtins` (all 11 built-in policies). You can
also specify `strict`, `balanced`, or `permissive`:

```bash
bash scripts/proxy-install.sh install balanced
```

### Configuration

All settings are in `~/.config/agentguard/proxy.env`:

```bash
# Full path to agentguard binary (auto-detected at install time)
AGENTGUARD_BIN=/path/to/agentguard

# Upstream LLM API base URL
#AGENTGUARD_UPSTREAM=https://api.githubcopilot.com

# Proxy listen port
#AGENTGUARD_PORT=8080

# Upstream request timeout (seconds)
#AGENTGUARD_TIMEOUT=300

# Actor name in audit entries
#AGENTGUARD_ACTOR=opencode-proxy

# Audit log directory
#AGENTGUARD_AUDIT_DIR=$HOME/.local/share/agentguard/audit
```

After editing, restart the service:

```bash
systemctl --user restart agentguard-proxy@builtins
```

### Management commands

```bash
# Status (with health check and policy count)
bash scripts/proxy-install.sh status

# Or use systemctl directly
systemctl --user status agentguard-proxy@builtins
systemctl --user restart agentguard-proxy@builtins
systemctl --user stop agentguard-proxy@builtins

# Live logs
journalctl --user -u agentguard-proxy@builtins -f
```

### Uninstall

```bash
bash scripts/proxy-install.sh uninstall
```

This stops and disables all preset instances, removes the service unit,
but preserves your config and audit logs.

### Systemd vs daemon script

| Feature | `proxy.sh` | systemd service |
|---------|-----------|-----------------|
| Auto-start on login | ❌ | ✅ |
| Crash recovery | ❌ | ✅ (auto-restart) |
| Log management | stdout/stderr | journald |
| Resource limits | ❌ | ✅ (cgroups) |
| Security hardening | ❌ | ✅ (NoNewPrivileges, PrivateTmp) |
| Quick testing | ✅ | ❌ |

Use `proxy.sh` for quick testing and one-off runs. Use the systemd
service for always-on protection in development or production.

---

## Verifying the Integration

After configuring, verify everything works:

```bash
# 1. Check proxy is healthy
bash scripts/proxy.sh health

# 2. Send a test request
curl -s http://127.0.0.1:8080/_status | python3 -m json.tool

# 3. Verify policy enforcement (should return 403)
curl -s http://127.0.0.1:8080/chat/completions \
  -H "Content-Type: application/json" \
  -d '{"messages":[{"role":"user","content":"My key is sk-abc123def456ghi789"}]}'

# 4. Check audit log
ls private/audit/proxy/*.jsonl

# 5. Verify audit chain integrity
agentguard audit verify private/audit/proxy/*.jsonl
```

---

## Combining with MCP Server

For maximum protection, run both layers:

```
AI Tool ──┬── LLM calls ──▶ AgentGuard Proxy ──▶ LLM API
          │
          └── Tool calls ──▶ AgentGuard MCP ──▶ OS (shell, files)
```

The MCP server and proxy each maintain their own audit logs. Both
are hash-chained and independently verifiable.

See [MCP Integration Guide](mcp-integration.md) for MCP setup details.
