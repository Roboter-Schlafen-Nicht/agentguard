#!/usr/bin/env bash
# Install/uninstall the AgentGuard proxy as a systemd user service.
#
# Usage:
#   proxy-install.sh [install|uninstall|status]
#
# install:   Copy service unit, enable, start
# uninstall: Stop, disable, remove service unit
# status:    Show service status and health

set -euo pipefail

SERVICE_NAME="agentguard-proxy"
DEFAULT_PRESET="builtins"
UNIT_DIR="${HOME}/.config/systemd/user"
ENV_DIR="${HOME}/.config/agentguard"
AUDIT_DIR="${HOME}/.local/share/agentguard/audit"

# Find the service template file (relative to this script)
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
UNIT_FILE="${SCRIPT_DIR}/../systemd/${SERVICE_NAME}@.service"

ACTION="${1:-status}"
PRESET="${2:-${DEFAULT_PRESET}}"
INSTANCE="${SERVICE_NAME}@${PRESET}"

do_install() {
    echo "Installing AgentGuard proxy service (preset: ${PRESET})..."

    # 1. Verify agentguard is available and resolve full path
    if ! command -v agentguard &>/dev/null; then
        echo "❌ agentguard not found in PATH" >&2
        echo "   Install: pip install agentguard[proxy]" >&2
        exit 1
    fi
    local agentguard_bin
    agentguard_bin="$(command -v agentguard)"

    # 2. Verify the unit file exists
    if [[ ! -f "$UNIT_FILE" ]]; then
        echo "❌ Service unit not found: ${UNIT_FILE}" >&2
        exit 1
    fi

    # 3. Create directories
    mkdir -p "${UNIT_DIR}" "${ENV_DIR}" "${AUDIT_DIR}"

    # 4. Copy service unit
    cp "${UNIT_FILE}" "${UNIT_DIR}/"
    echo "   ✓ Copied service unit to ${UNIT_DIR}/"

    # 5. Create default env file if it doesn't exist
    if [[ ! -f "${ENV_DIR}/proxy.env" ]]; then
        cat > "${ENV_DIR}/proxy.env" << ENV
# AgentGuard Proxy Configuration
# Uncomment and modify to override defaults.

# Full path to agentguard binary (auto-detected at install time)
AGENTGUARD_BIN=${agentguard_bin}

# Upstream LLM API base URL
#AGENTGUARD_UPSTREAM=https://api.githubcopilot.com

# Proxy listen port
#AGENTGUARD_PORT=8080

# Upstream request timeout (seconds)
#AGENTGUARD_TIMEOUT=300

# Actor name in audit entries
#AGENTGUARD_ACTOR=opencode-proxy

# Audit log directory
#AGENTGUARD_AUDIT_DIR=\$HOME/.local/share/agentguard/audit
ENV
        echo "   ✓ Created default config at ${ENV_DIR}/proxy.env"
    else
        # Ensure AGENTGUARD_BIN is set even if env file already exists
        if ! grep -q '^AGENTGUARD_BIN=' "${ENV_DIR}/proxy.env"; then
            echo "" >> "${ENV_DIR}/proxy.env"
            echo "# Full path to agentguard binary (auto-detected at install time)" >> "${ENV_DIR}/proxy.env"
            echo "AGENTGUARD_BIN=${agentguard_bin}" >> "${ENV_DIR}/proxy.env"
            echo "   ✓ Added AGENTGUARD_BIN to existing config"
        fi
        echo "   ✓ Config exists at ${ENV_DIR}/proxy.env (not overwritten)"
    fi

    # 6. Reload systemd, enable and start
    systemctl --user daemon-reload
    systemctl --user enable "${INSTANCE}" 2>/dev/null
    systemctl --user start "${INSTANCE}"

    echo ""
    echo "✅ AgentGuard proxy installed and running"
    echo ""
    echo "   Service: ${INSTANCE}"
    echo "   Config:  ${ENV_DIR}/proxy.env"
    echo "   Audit:   ${AUDIT_DIR}/"
    echo "   Logs:    journalctl --user -u ${INSTANCE} -f"
    echo ""

    # 7. Wait for health and show status
    sleep 2
    local port
    port=$(grep -oP 'AGENTGUARD_PORT=\K\d+' "${ENV_DIR}/proxy.env" 2>/dev/null || echo "8080")
    if curl -sf "http://127.0.0.1:${port}/_health" >/dev/null 2>&1; then
        local health
        health=$(curl -s "http://127.0.0.1:${port}/_health")
        local policies
        policies=$(echo "$health" | python3 -c "import json,sys; print(json.load(sys.stdin).get('policies_loaded', '?'))" 2>/dev/null || echo "?")
        echo "   Health:  ✅ ${policies} policies loaded"
    else
        echo "   Health:  ⏳ starting up (check: curl http://127.0.0.1:${port}/_health)"
    fi

    echo ""
    echo "Commands:"
    echo "   systemctl --user status ${INSTANCE}    # Status"
    echo "   systemctl --user restart ${INSTANCE}   # Restart"
    echo "   systemctl --user stop ${INSTANCE}      # Stop"
    echo "   journalctl --user -u ${INSTANCE} -f    # Live logs"
}

do_uninstall() {
    echo "Uninstalling AgentGuard proxy service..."

    # Stop and disable all presets
    for preset in builtins strict balanced permissive; do
        local inst="${SERVICE_NAME}@${preset}"
        if systemctl --user is-active "${inst}" &>/dev/null; then
            systemctl --user stop "${inst}"
            echo "   ✓ Stopped ${inst}"
        fi
        if systemctl --user is-enabled "${inst}" &>/dev/null 2>&1; then
            systemctl --user disable "${inst}" 2>/dev/null
            echo "   ✓ Disabled ${inst}"
        fi
    done

    # Remove unit file
    if [[ -f "${UNIT_DIR}/${SERVICE_NAME}@.service" ]]; then
        rm "${UNIT_DIR}/${SERVICE_NAME}@.service"
        echo "   ✓ Removed service unit"
    fi

    systemctl --user daemon-reload

    echo ""
    echo "✅ AgentGuard proxy service removed"
    echo ""
    echo "   Config preserved at: ${ENV_DIR}/proxy.env"
    echo "   Audit logs at:       ${AUDIT_DIR}/"
    echo "   (Remove manually if no longer needed)"
}

do_status() {
    echo "AgentGuard Proxy Service Status"
    echo "================================"
    echo ""

    local found=false
    for preset in builtins strict balanced permissive; do
        local inst="${SERVICE_NAME}@${preset}"
        if systemctl --user is-active "${inst}" &>/dev/null; then
            found=true
            echo "● ${inst}: active (running)"
            systemctl --user show "${inst}" --property=MainPID,ActiveEnterTimestamp \
                --no-pager 2>/dev/null | sed 's/^/  /'

            # Health check
            local port
            port=$(grep -oP 'AGENTGUARD_PORT=\K\d+' "${ENV_DIR}/proxy.env" 2>/dev/null || echo "8080")
            if curl -sf "http://127.0.0.1:${port}/_status" >/dev/null 2>&1; then
                curl -s "http://127.0.0.1:${port}/_status" | python3 -c "
import json, sys
d = json.load(sys.stdin)
print(f\"  Upstream: {d.get('upstream', '?')}\")
print(f\"  Policies: {d.get('policies_loaded', '?')} loaded\")
print(f\"  Audit:    {d.get('audit_entries', 0)} entries this session\")
" 2>/dev/null
            fi
            echo ""
        elif systemctl --user is-enabled "${inst}" &>/dev/null 2>&1; then
            echo "○ ${inst}: enabled (not running)"
            echo ""
        fi
    done

    if [[ "$found" == "false" ]]; then
        # Check if unit is installed at all
        if [[ -f "${UNIT_DIR}/${SERVICE_NAME}@.service" ]]; then
            echo "Service unit installed but no instance is active."
            echo ""
            echo "Start with: systemctl --user start ${SERVICE_NAME}@builtins"
        else
            echo "Service not installed."
            echo ""
            echo "Install with: bash scripts/proxy-install.sh install"
        fi
    fi
}

case "$ACTION" in
    install)   do_install ;;
    uninstall) do_uninstall ;;
    status)    do_status ;;
    *)
        echo "Usage: proxy-install.sh [install|uninstall|status] [preset]"
        echo ""
        echo "  install [preset]  Install and start (default preset: builtins)"
        echo "  uninstall         Stop, disable, and remove"
        echo "  status            Show current status"
        echo ""
        echo "Presets: builtins, strict, balanced, permissive"
        exit 1
        ;;
esac
