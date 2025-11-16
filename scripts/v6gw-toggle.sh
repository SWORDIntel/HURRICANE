#!/bin/bash
# HURRICANE v6-gatewayd Toggle Script
# Smart daemon control: auto-detects state and toggles
# - Starts daemon if stopped
# - Stops daemon if running
# - Shows status and helpful info

set -e

DAEMON_NAME="v6-gatewayd"
SERVICE_NAME="v6-gatewayd.service"
API_URL="http://localhost:8642"
WEBUI_URL="http://localhost:8642/ui"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_header() {
    echo -e "${BLUE}╔════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║${NC}  HURRICANE v6-gatewayd Control                  ${BLUE}║${NC}"
    echo -e "${BLUE}╚════════════════════════════════════════════════════╝${NC}"
    echo ""
}

check_root() {
    if [ "$EUID" -ne 0 ]; then
        echo -e "${RED}✗ Error: This script must be run as root${NC}"
        echo "  Usage: sudo $0"
        exit 1
    fi
}

is_running() {
    systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null
}

is_enabled() {
    systemctl is-enabled --quiet "$SERVICE_NAME" 2>/dev/null
}

get_status() {
    if is_running; then
        echo -e "${GREEN}RUNNING${NC}"
    else
        echo -e "${RED}STOPPED${NC}"
    fi
}

show_status() {
    local status=$(get_status)
    local enabled_status="disabled"

    if is_enabled; then
        enabled_status="${GREEN}enabled${NC}"
    else
        enabled_status="${YELLOW}disabled${NC}"
    fi

    echo -e "Daemon Status: $status"
    echo -e "Auto-start:    $enabled_status"

    if is_running; then
        echo ""
        echo "API Endpoints:"
        echo "  Health:  curl $API_URL/health"
        echo "  Tunnels: curl $API_URL/tunnels"
        echo "  WebUI:   $WEBUI_URL"

        # Try to fetch health status
        if command -v curl >/dev/null 2>&1; then
            echo ""
            echo -e "${BLUE}Current Health:${NC}"
            curl -s "$API_URL/health" 2>/dev/null | head -10 || echo "  (API not responding)"
        fi
    fi
}

start_daemon() {
    echo -e "${YELLOW}▶ Starting $DAEMON_NAME...${NC}"

    systemctl start "$SERVICE_NAME"

    # Wait for daemon to start
    sleep 2

    if is_running; then
        echo -e "${GREEN}✓ Daemon started successfully${NC}"
        echo ""

        # Enable auto-start if not already enabled
        if ! is_enabled; then
            echo -e "${YELLOW}⚡ Enabling auto-start on boot...${NC}"
            systemctl enable "$SERVICE_NAME"
            echo -e "${GREEN}✓ Auto-start enabled${NC}"
        fi

        echo ""
        echo -e "${GREEN}Access the WebUI at: $WEBUI_URL${NC}"
        echo ""
        show_status
    else
        echo -e "${RED}✗ Failed to start daemon${NC}"
        echo ""
        echo "Check logs with:"
        echo "  sudo journalctl -u $SERVICE_NAME -n 50"
        exit 1
    fi
}

stop_daemon() {
    echo -e "${YELLOW}■ Stopping $DAEMON_NAME...${NC}"

    systemctl stop "$SERVICE_NAME"

    # Wait for daemon to stop
    sleep 1

    if ! is_running; then
        echo -e "${GREEN}✓ Daemon stopped successfully${NC}"
        echo ""
        show_status
    else
        echo -e "${RED}✗ Failed to stop daemon${NC}"
        exit 1
    fi
}

restart_daemon() {
    echo -e "${YELLOW}↻ Restarting $DAEMON_NAME...${NC}"

    systemctl restart "$SERVICE_NAME"

    sleep 2

    if is_running; then
        echo -e "${GREEN}✓ Daemon restarted successfully${NC}"
        echo ""
        show_status
    else
        echo -e "${RED}✗ Failed to restart daemon${NC}"
        exit 1
    fi
}

toggle_daemon() {
    if is_running; then
        # Daemon is running, stop it
        stop_daemon
    else
        # Daemon is stopped, start it
        start_daemon
    fi
}

show_logs() {
    echo -e "${BLUE}Last 30 log entries:${NC}"
    echo ""
    journalctl -u "$SERVICE_NAME" -n 30 --no-pager
}

# Main
print_header
check_root

case "${1:-toggle}" in
    start)
        start_daemon
        ;;
    stop)
        stop_daemon
        ;;
    restart)
        restart_daemon
        ;;
    status)
        show_status
        ;;
    logs)
        show_logs
        ;;
    toggle|"")
        toggle_daemon
        ;;
    *)
        echo "Usage: $0 [start|stop|restart|toggle|status|logs]"
        echo ""
        echo "Commands:"
        echo "  toggle   - Auto-detect and toggle daemon state (default)"
        echo "  start    - Start the daemon"
        echo "  stop     - Stop the daemon"
        echo "  restart  - Restart the daemon"
        echo "  status   - Show daemon status"
        echo "  logs     - Show recent logs"
        exit 1
        ;;
esac
