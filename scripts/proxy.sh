#!/usr/bin/env bash
# AgentGuard LLM API Proxy — daemon management
# Usage: proxy.sh {start|stop|status|health} [OPTIONS]
#
# Starts the AgentGuard proxy as a background daemon, manages its
# lifecycle, and checks health. Designed for integration with OpenCode
# and other AI coding tools.
#
# Options (for 'start'):
#   --upstream URL      Upstream LLM API (default: https://api.githubcopilot.com)
#   --port PORT         Proxy port (default: 8080)
#   --preset LEVEL      Protection preset: strict|balanced|permissive
#   --builtins          Load all built-in policies (default if no --preset)
#   --scan-responses    Scan upstream responses (default: enabled)
#   --no-scan-responses Disable response scanning
#   --audit-dir DIR     Audit log directory (default: ./private/audit/proxy)
#   --actor NAME        Actor name for audit (default: opencode-proxy)
#   --timeout SECS      Upstream timeout (default: 300)
#   --pid-dir DIR       Directory for PID/log files (default: ./private/run)
#
# Environment:
#   AGENTGUARD_PROXY_UPSTREAM   Override default upstream URL
#   AGENTGUARD_PROXY_PORT       Override default port
#   AGENTGUARD_PROXY_PRESET     Override default preset
#   AGENTGUARD_PROXY_AUDIT_DIR  Override default audit directory

set -euo pipefail

# ── Defaults ─────────────────────────────────────────────────────────

UPSTREAM="${AGENTGUARD_PROXY_UPSTREAM:-https://api.githubcopilot.com}"
PORT="${AGENTGUARD_PROXY_PORT:-8080}"
PRESET="${AGENTGUARD_PROXY_PRESET:-}"
USE_BUILTINS=true
SCAN_RESPONSES=true
AUDIT_DIR="${AGENTGUARD_PROXY_AUDIT_DIR:-./private/audit/proxy}"
ACTOR="opencode-proxy"
TIMEOUT=300
PID_DIR="./private/run"

# ── Parse arguments ─────────────────────────────────────────────────

ACTION="${1:-help}"
shift 2>/dev/null || true

while [[ $# -gt 0 ]]; do
    case "$1" in
        --upstream)       UPSTREAM="$2"; shift 2 ;;
        --port)           PORT="$2"; shift 2 ;;
        --preset)         PRESET="$2"; USE_BUILTINS=false; shift 2 ;;
        --builtins)       USE_BUILTINS=true; PRESET=""; shift ;;
        --scan-responses) SCAN_RESPONSES=true; shift ;;
        --no-scan-responses) SCAN_RESPONSES=false; shift ;;
        --audit-dir)      AUDIT_DIR="$2"; shift 2 ;;
        --actor)          ACTOR="$2"; shift 2 ;;
        --timeout)        TIMEOUT="$2"; shift 2 ;;
        --pid-dir)        PID_DIR="$2"; shift 2 ;;
        *)                echo "Unknown option: $1" >&2; exit 1 ;;
    esac
done

# ── Paths ────────────────────────────────────────────────────────────

PID_FILE="${PID_DIR}/proxy.pid"
LOG_FILE="${PID_DIR}/proxy.log"

# ── Functions ────────────────────────────────────────────────────────

is_running() {
    if [[ -f "$PID_FILE" ]]; then
        local pid
        pid=$(cat "$PID_FILE")
        if kill -0 "$pid" 2>/dev/null; then
            return 0
        fi
        # Stale PID file
        rm -f "$PID_FILE"
    fi
    return 1
}

get_pid() {
    if [[ -f "$PID_FILE" ]]; then
        cat "$PID_FILE"
    fi
}

do_start() {
    if is_running; then
        echo "AgentGuard proxy already running (PID: $(get_pid))"
        echo "Use 'proxy.sh stop' first, or 'proxy.sh status' for details."
        return 1
    fi

    mkdir -p "$AUDIT_DIR" "$PID_DIR"

    # Build command — use the agentguard CLI (supports --preset)
    local cmd=(agentguard proxy "$UPSTREAM"
        --port "$PORT"
        --audit-dir "$AUDIT_DIR"
        --actor "$ACTOR"
        --timeout "$TIMEOUT"
    )

    if [[ -n "$PRESET" ]]; then
        cmd+=(--preset "$PRESET")
    elif [[ "$USE_BUILTINS" == "true" ]]; then
        cmd+=(--builtins)
    fi

    if [[ "$SCAN_RESPONSES" == "true" ]]; then
        cmd+=(--scan-responses)
    fi

    # Start as background daemon
    setsid "${cmd[@]}" </dev/null > "$LOG_FILE" 2>&1 &
    local pid=$!
    echo "$pid" > "$PID_FILE"

    # Wait for readiness (up to 10 seconds)
    local attempts=0
    local max_attempts=20
    while [[ $attempts -lt $max_attempts ]]; do
        sleep 0.5
        # Check if process died
        if ! kill -0 "$pid" 2>/dev/null; then
            echo "❌ Proxy failed to start. Log:" >&2
            tail -20 "$LOG_FILE" >&2
            rm -f "$PID_FILE"
            return 1
        fi
        # Check health endpoint
        if curl -sf "http://127.0.0.1:${PORT}/_health" >/dev/null 2>&1; then
            local health
            health=$(curl -s "http://127.0.0.1:${PORT}/_health")
            local policies
            policies=$(echo "$health" | python3 -c "import json,sys; print(json.load(sys.stdin).get('policies_loaded', '?'))" 2>/dev/null || echo "?")
            echo "✅ AgentGuard proxy started"
            echo "   PID:      $pid"
            echo "   Port:     $PORT"
            echo "   Upstream: $UPSTREAM"
            echo "   Policies: $policies loaded"
            echo "   Audit:    $AUDIT_DIR"
            echo "   Log:      $LOG_FILE"
            return 0
        fi
        attempts=$((attempts + 1))
    done

    echo "⚠️  Proxy started (PID: $pid) but health check not responding after 10s" >&2
    echo "   Check log: $LOG_FILE" >&2
    return 1
}

do_stop() {
    if ! is_running; then
        echo "AgentGuard proxy is not running"
        return 0
    fi

    local pid
    pid=$(get_pid)
    echo "Stopping AgentGuard proxy (PID: $pid)..."
    kill "$pid" 2>/dev/null

    # Wait for graceful shutdown (up to 5 seconds)
    local attempts=0
    while [[ $attempts -lt 10 ]]; do
        if ! kill -0 "$pid" 2>/dev/null; then
            rm -f "$PID_FILE"
            echo "✅ Proxy stopped"
            return 0
        fi
        sleep 0.5
        attempts=$((attempts + 1))
    done

    # Force kill
    kill -9 "$pid" 2>/dev/null
    rm -f "$PID_FILE"
    echo "✅ Proxy force-stopped"
}

do_status() {
    if ! is_running; then
        echo "AgentGuard proxy is not running"
        return 1
    fi

    local pid
    pid=$(get_pid)
    echo "AgentGuard proxy is running (PID: $pid)"

    # Get detailed status from the proxy
    if curl -sf "http://127.0.0.1:${PORT}/_status" >/dev/null 2>&1; then
        echo ""
        curl -s "http://127.0.0.1:${PORT}/_status" | python3 -c "
import json, sys
data = json.load(sys.stdin)
print(f\"   Session:  {data.get('session_id', '?')}\")
print(f\"   Actor:    {data.get('actor', '?')}\")
print(f\"   Upstream: {data.get('upstream', '?')}\")
print(f\"   Policies: {data.get('policies_loaded', '?')} loaded\")
names = data.get('policy_names', [])
if names:
    for n in names:
        print(f\"             - {n}\")
print(f\"   Audit:    {data.get('audit_entries', 0)} entries this session\")
print(f\"   Scanning: responses={'yes' if data.get('scan_responses') else 'no'}\")
" 2>/dev/null
    else
        echo "   (health endpoint not responding)"
    fi
}

do_health() {
    if ! curl -sf "http://127.0.0.1:${PORT}/_health" >/dev/null 2>&1; then
        echo "UNHEALTHY: proxy not responding on port $PORT"
        return 1
    fi
    echo "HEALTHY"
    curl -s "http://127.0.0.1:${PORT}/_health" | python3 -m json.tool 2>/dev/null
}

do_help() {
    echo "AgentGuard LLM API Proxy — daemon management"
    echo ""
    echo "Usage: proxy.sh {start|stop|status|health} [OPTIONS]"
    echo ""
    echo "Commands:"
    echo "  start    Start the proxy daemon"
    echo "  stop     Stop the proxy daemon"
    echo "  status   Show proxy status and loaded policies"
    echo "  health   Quick health check (for scripts)"
    echo ""
    echo "Options (for 'start'):"
    echo "  --upstream URL       Upstream LLM API (default: https://api.githubcopilot.com)"
    echo "  --port PORT          Proxy port (default: 8080)"
    echo "  --preset LEVEL       Protection preset: strict|balanced|permissive"
    echo "  --builtins           Load all built-in policies (default)"
    echo "  --scan-responses     Enable response scanning (default)"
    echo "  --no-scan-responses  Disable response scanning"
    echo "  --audit-dir DIR      Audit log directory"
    echo "  --actor NAME         Actor name for audit entries"
    echo "  --timeout SECS       Upstream request timeout (default: 300)"
    echo "  --pid-dir DIR        Directory for PID and log files"
    echo ""
    echo "Environment variables:"
    echo "  AGENTGUARD_PROXY_UPSTREAM   Override upstream URL"
    echo "  AGENTGUARD_PROXY_PORT       Override port"
    echo "  AGENTGUARD_PROXY_PRESET     Override preset"
    echo "  AGENTGUARD_PROXY_AUDIT_DIR  Override audit directory"
}

# ── Main ─────────────────────────────────────────────────────────────

case "$ACTION" in
    start)  do_start ;;
    stop)   do_stop ;;
    status) do_status ;;
    health) do_health ;;
    help|--help|-h) do_help ;;
    *)
        echo "Unknown command: $ACTION" >&2
        echo "Usage: proxy.sh {start|stop|status|health}" >&2
        exit 1
        ;;
esac
