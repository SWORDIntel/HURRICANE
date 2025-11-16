#!/bin/bash
# HURRICANE v6-gatewayd Master Build and Launch Script
# Complete orchestration: builds, installs, configures, and launches everything
# - Auto-installs dependencies
# - Builds daemon and utilities
# - Encrypts and installs credentials
# - Launches daemon
# - Enables HE auto-update timer
# - Smart toggle: stops if running, starts if stopped

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
DAEMON_SERVICE="v6-gatewayd.service"
HE_TIMER="he-update.timer"
HE_SERVICE="he-update.service"
API_URL="http://localhost:8642"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

print_banner() {
    echo -e "${CYAN}"
    cat << 'EOF'
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║   ██╗  ██╗██╗   ██╗██████╗ ██████╗ ██╗ ██████╗ █████╗ ███╗  ║
║   ██║  ██║██║   ██║██╔══██╗██╔══██╗██║██╔════╝██╔══██╗████╗ ║
║   ███████║██║   ██║██████╔╝██████╔╝██║██║     ███████║██╔██╗║
║   ██╔══██║██║   ██║██╔══██╗██╔══██╗██║██║     ██╔══██║██║╚██║
║   ██║  ██║╚██████╔╝██║  ██║██║  ██║██║╚██████╗██║  ██║██║ ╚█║
║   ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚╝
║                                                              ║
║          v6-gatewayd - IPv6 Tunnel Gateway Daemon           ║
║              Build, Install & Launch Orchestrator           ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
EOF
    echo -e "${NC}"
}

log_info() {
    echo -e "${BLUE}ℹ${NC} $1"
}

log_success() {
    echo -e "${GREEN}✓${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}⚠${NC} $1"
}

log_error() {
    echo -e "${RED}✗${NC} $1"
}

log_step() {
    echo ""
    echo -e "${BOLD}${CYAN}▶ $1${NC}"
    echo -e "${CYAN}════════════════════════════════════════════════════${NC}"
}

check_root() {
    if [ "$EUID" -ne 0 ]; then
        log_error "This script must be run as root"
        echo "  Usage: sudo $0"
        exit 1
    fi
}

is_daemon_running() {
    systemctl is-active --quiet "$DAEMON_SERVICE" 2>/dev/null
}

is_daemon_installed() {
    [ -f /usr/local/bin/v6-gatewayd ] && [ -f /etc/systemd/system/"$DAEMON_SERVICE" ]
}

is_built() {
    [ -f "$PROJECT_DIR/v6-gatewayd" ] && [ -f "$PROJECT_DIR/v6gw-keygen" ]
}

check_libcurl() {
    pkg-config --exists libcurl 2>/dev/null
}

build_project() {
    log_step "Building Project"

    cd "$PROJECT_DIR"

    # Check if already built
    if is_built; then
        log_info "Project already built, rebuilding..."
        make clean
    fi

    # Build
    log_info "Compiling daemon and utilities..."
    make -j$(nproc) 2>&1 | grep -E "(Built|Error|fatal|warning)" || true

    if is_built; then
        log_success "Build completed successfully"
        ls -lh v6-gatewayd v6gw-keygen
    else
        log_error "Build failed"
        exit 1
    fi
}

install_project() {
    log_step "Installing to System"

    cd "$PROJECT_DIR"

    log_info "Installing binaries and configuration..."
    make install

    log_success "Installation complete"
}

setup_encrypted_credentials() {
    log_step "Setting Up Encrypted Credentials"

    # Make encryption script executable
    chmod +x "$SCRIPT_DIR/he-creds-encrypt.sh"

    # Check if credentials already encrypted
    if [ -f /etc/v6-gatewayd-he.env.enc ]; then
        log_info "Encrypted credentials already exist"
        return
    fi

    log_info "Installing SWORD HQ tunnel credentials..."
    log_info "  Username: SWORDIntel"
    log_info "  Tunnel ID: 940962"

    "$SCRIPT_DIR/he-creds-encrypt.sh" install

    log_success "Credentials encrypted and secured"
}

update_systemd_service() {
    log_step "Updating Systemd Service for Encrypted Credentials"

    local service_file="/etc/systemd/system/$HE_SERVICE"

    # Update he-update.service to decrypt credentials at runtime
    cat > "$service_file" << 'EOF'
[Unit]
Description=Hurricane Electric Tunnel Endpoint Update
Documentation=https://github.com/SWORDIntel/HURRICANE
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot

# Decrypt credentials and execute update
ExecStart=/bin/bash -c '\
    KEY_FILE=/var/lib/v6-gatewayd/he.key; \
    ENC_FILE=/etc/v6-gatewayd-he.env.enc; \
    if [ ! -f "$ENC_FILE" ] || [ ! -f "$KEY_FILE" ]; then \
        echo "Error: Encrypted credentials or key not found"; \
        exit 1; \
    fi; \
    eval $(openssl enc -aes-256-cbc -d -pbkdf2 -iter 100000 -in "$ENC_FILE" -pass "file:$KEY_FILE" | grep -E "^HE_"); \
    /usr/local/bin/he-update -u "$HE_USERNAME" -p "$HE_PASSWORD" -t "$HE_TUNNEL_ID" -c /var/lib/v6-gatewayd/he-ip.cache -v'

# Security hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/v6-gatewayd

# Network access required
PrivateNetwork=false

# Resource limits
MemoryMax=64M
CPUQuota=50%

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=he-update

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    log_success "Systemd service updated for encrypted credentials"
}

start_daemon() {
    log_step "Starting Daemon"

    systemctl start "$DAEMON_SERVICE"
    sleep 2

    if is_daemon_running; then
        log_success "Daemon started successfully"

        # Enable auto-start
        systemctl enable "$DAEMON_SERVICE" 2>/dev/null || true
        log_success "Daemon enabled for auto-start on boot"

        # Show status
        echo ""
        log_info "API: $API_URL/health"
        log_info "WebUI: $API_URL/ui"
    else
        log_error "Failed to start daemon"
        echo ""
        log_info "Check logs with: sudo journalctl -u $DAEMON_SERVICE -n 50"
        exit 1
    fi
}

stop_daemon() {
    log_step "Stopping Daemon"

    systemctl stop "$DAEMON_SERVICE"
    sleep 1

    if ! is_daemon_running; then
        log_success "Daemon stopped successfully"
    else
        log_error "Failed to stop daemon"
        exit 1
    fi
}

enable_he_autoupdate() {
    log_step "Enabling Hurricane Electric Auto-Update"

    if ! check_libcurl; then
        log_warning "libcurl not available - HE auto-update disabled"
        log_info "Install with: sudo apt-get install libcurl4-openssl-dev"
        return
    fi

    if [ ! -f /usr/local/bin/he-update ]; then
        log_warning "he-update binary not found - skipping auto-update setup"
        return
    fi

    # Enable and start timer
    systemctl enable "$HE_TIMER"
    systemctl start "$HE_TIMER"

    log_success "HE auto-update timer enabled (runs every 15 minutes)"
    log_info "Check status: systemctl status $HE_TIMER"
    log_info "View logs: journalctl -u $HE_SERVICE -f"
}

show_status() {
    log_step "System Status"

    # Daemon status
    if is_daemon_running; then
        echo -e "Daemon:       ${GREEN}RUNNING${NC}"
    else
        echo -e "Daemon:       ${RED}STOPPED${NC}"
    fi

    # HE timer status
    if systemctl is-active --quiet "$HE_TIMER" 2>/dev/null; then
        echo -e "HE Auto-Update: ${GREEN}ENABLED${NC}"
    else
        echo -e "HE Auto-Update: ${YELLOW}DISABLED${NC}"
    fi

    echo ""

    if is_daemon_running; then
        # Try to get health status
        if command -v curl >/dev/null 2>&1; then
            log_info "Health Check:"
            curl -s "$API_URL/health" 2>/dev/null | head -20 || log_warning "API not responding"
        fi
    fi
}

# Main orchestration
main() {
    print_banner
    check_root

    # Detect mode: toggle if already installed
    if is_daemon_installed && is_daemon_running; then
        log_info "Daemon is running - stopping..."
        stop_daemon
        show_status
        exit 0
    fi

    # Full build and launch sequence
    if ! is_built; then
        build_project
    else
        log_info "Project already built, skipping build"
    fi

    if ! is_daemon_installed; then
        install_project
    else
        log_info "Daemon already installed, skipping installation"
    fi

    setup_encrypted_credentials
    update_systemd_service
    start_daemon
    enable_he_autoupdate

    echo ""
    log_step "Launch Complete"
    echo ""
    show_status

    echo ""
    echo -e "${GREEN}${BOLD}╔════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}${BOLD}║  HURRICANE v6-gatewayd is now running!            ║${NC}"
    echo -e "${GREEN}${BOLD}╚════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "  ${CYAN}WebUI:${NC}  $API_URL/ui"
    echo -e "  ${CYAN}Health:${NC} $API_URL/health"
    echo -e "  ${CYAN}Logs:${NC}   sudo journalctl -u $DAEMON_SERVICE -f"
    echo ""
    echo -e "${YELLOW}Run this script again to toggle the daemon (stop if running, start if stopped)${NC}"
    echo ""
}

main "$@"
