#!/bin/bash
set -euo pipefail

# =============================================================================
# Hostman Agent Provisioning Script
# Idempotent - safe to run multiple times
# =============================================================================

AGENT_TOKEN="${1:-}"
SAAS_URL="${2:-http://localhost}"
SERVER_ID="${3:-}"

if [[ -z "$AGENT_TOKEN" ]]; then
    echo "Usage: install.sh <agent_token> [saas_url] [server_id]"
    exit 1
fi

# -----------------------------------------------------------------------------
# Helper Functions
# -----------------------------------------------------------------------------
log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"; }
is_installed() { dpkg -l "$1" 2>/dev/null | grep -q "^ii"; }

# -----------------------------------------------------------------------------
# System Updates
# -----------------------------------------------------------------------------
log "Updating package lists..."
apt-get update -qq

# -----------------------------------------------------------------------------
# Required Packages (Idempotent)
# -----------------------------------------------------------------------------
PACKAGES=(
    curl
    git
    unzip
    ufw
    fail2ban
)

for pkg in "${PACKAGES[@]}"; do
    if is_installed "$pkg"; then
        log "$pkg already installed, skipping"
    else
        log "Installing $pkg..."
        apt-get install -y -qq "$pkg"
    fi
done

# -----------------------------------------------------------------------------
# Agent User (Idempotent)
# -----------------------------------------------------------------------------
if ! id "hostman" &>/dev/null; then
    log "Creating hostman user..."
    useradd -r -s /bin/bash -d /opt/hostman hostman
    mkdir -p /opt/hostman
    chown hostman:hostman /opt/hostman
fi

# -----------------------------------------------------------------------------
# Agent Directory Structure
# -----------------------------------------------------------------------------
AGENT_DIR="/opt/hostman"
mkdir -p "$AGENT_DIR"

# -----------------------------------------------------------------------------
# Download Agent Binary (if not exists or force update)
# -----------------------------------------------------------------------------
AGENT_BIN="$AGENT_DIR/sentinel"

if [[ ! -f "$AGENT_BIN" ]] || [[ "${FORCE_UPDATE:-}" == "1" ]]; then
    log "Downloading agent binary..."
    # In production, download from SaaS
    # curl -fsSL "$SAAS_URL/downloads/sentinel-linux-amd64" -o "$AGENT_BIN"

    # For now, check if binary exists locally
    if [[ -f "/tmp/sentinel" ]]; then
        cp /tmp/sentinel "$AGENT_BIN"
    else
        log "Warning: Agent binary not found. Please copy manually to $AGENT_BIN"
    fi
fi

if [[ -f "$AGENT_BIN" ]]; then
    chmod +x "$AGENT_BIN"
fi

# -----------------------------------------------------------------------------
# Agent Configuration
# -----------------------------------------------------------------------------
log "Writing agent configuration..."
cat > "$AGENT_DIR/agent.yaml" << EOF
saas_url: $SAAS_URL
agent_token: $AGENT_TOKEN
server_id: $SERVER_ID
poll_interval: 5s
stats_interval: 60s
log_level: info
EOF

chown hostman:hostman "$AGENT_DIR/agent.yaml"
chmod 600 "$AGENT_DIR/agent.yaml"

# -----------------------------------------------------------------------------
# Systemd Service
# -----------------------------------------------------------------------------
log "Setting up systemd service..."
cat > /etc/systemd/system/hostman-agent.service << 'EOF'
[Unit]
Description=Hostman Sentinel Agent
After=network.target

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=/opt/hostman
ExecStart=/opt/hostman/sentinel
Restart=always
RestartSec=5

# Environment
Environment=HOSTMAN_SAAS_URL=
Environment=HOSTMAN_AGENT_TOKEN=
Environment=HOSTMAN_SERVER_ID=

[Install]
WantedBy=multi-user.target
EOF

# Update service file with actual values
sed -i "s|HOSTMAN_SAAS_URL=|HOSTMAN_SAAS_URL=$SAAS_URL|" /etc/systemd/system/hostman-agent.service
sed -i "s|HOSTMAN_AGENT_TOKEN=|HOSTMAN_AGENT_TOKEN=$AGENT_TOKEN|" /etc/systemd/system/hostman-agent.service
sed -i "s|HOSTMAN_SERVER_ID=|HOSTMAN_SERVER_ID=$SERVER_ID|" /etc/systemd/system/hostman-agent.service

systemctl daemon-reload
systemctl enable hostman-agent

# Start only if binary exists
if [[ -f "$AGENT_BIN" ]]; then
    systemctl restart hostman-agent
    log "Agent service started"
else
    log "Warning: Agent binary not found, service not started"
fi

# -----------------------------------------------------------------------------
# Firewall Setup (Idempotent)
# -----------------------------------------------------------------------------
log "Configuring firewall..."
ufw --force enable
ufw default deny incoming
ufw default allow outgoing
ufw allow ssh
ufw allow http
ufw allow https

# -----------------------------------------------------------------------------
# Complete
# -----------------------------------------------------------------------------
log "Installation complete!"
if systemctl is-active --quiet hostman-agent; then
    log "Agent status: running"
else
    log "Agent status: not running (binary may be missing)"
fi
