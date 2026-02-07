#!/bin/sh
#######################################################################
# Skynet OTX Threat Collector - Runner Script
# For ASUS routers with AsusWRT-Merlin firmware
#
# This script manages the Python collector and integrates with
# the router's job scheduler (cron)
#
# Installation:
#   1. Copy to USB drive: /tmp/mnt/OTX/skynet_otx_runner.sh
#   2. Make executable: chmod +x /tmp/mnt/OTX/skynet_otx_runner.sh
#   3. Add to cron or services-start
#
# Usage:
#   ./skynet_otx_runner.sh start     # Start daemon mode
#   ./skynet_otx_runner.sh stop      # Stop daemon
#   ./skynet_otx_runner.sh run       # Run once
#   ./skynet_otx_runner.sh status    # Check status
#   ./skynet_otx_runner.sh install   # Install to cron
#   ./skynet_otx_runner.sh uninstall # Remove from cron
#######################################################################

# Configuration
SCRIPT_DIR="/tmp/mnt/OTX"
PYTHON_BIN="/opt/bin/python3"
COLLECTOR_SCRIPT="${SCRIPT_DIR}/skynet_otx_splunk.py"
CONFIG_FILE="${SCRIPT_DIR}/skynet_otx_config.json"
PID_FILE="${SCRIPT_DIR}/skynet_otx.pid"
LOG_FILE="${SCRIPT_DIR}/skynet_otx.log"

# Collection interval in seconds (5 minutes)
INTERVAL=300

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

#######################################################################
# Helper Functions
#######################################################################

log_msg() {
    echo -e "${GREEN}[SKYNET-OTX]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[SKYNET-OTX]${NC} $1"
}

log_error() {
    echo -e "${RED}[SKYNET-OTX]${NC} $1"
}

check_prerequisites() {
    # Check Python
    if [ ! -x "$PYTHON_BIN" ]; then
        log_error "Python3 not found at $PYTHON_BIN"
        log_warn "Install with: opkg install python3 python3-pip"
        return 1
    fi

    # Check collector script
    if [ ! -f "$COLLECTOR_SCRIPT" ]; then
        log_error "Collector script not found: $COLLECTOR_SCRIPT"
        return 1
    fi

    # Check requests library
    $PYTHON_BIN -c "import requests" 2>/dev/null
    if [ $? -ne 0 ]; then
        log_error "Python 'requests' library not installed"
        log_warn "Install with: opkg install python3-requests"
        log_warn "         or: pip3 install requests"
        return 1
    fi

    # Check config file
    if [ ! -f "$CONFIG_FILE" ]; then
        log_warn "Config file not found, using defaults: $CONFIG_FILE"
    fi

    return 0
}

get_pid() {
    if [ -f "$PID_FILE" ]; then
        cat "$PID_FILE" 2>/dev/null
    fi
}

is_running() {
    local pid=$(get_pid)
    if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
        return 0
    fi
    return 1
}

#######################################################################
# Main Functions
#######################################################################

do_start() {
    log_msg "Starting Skynet OTX Collector daemon..."

    if is_running; then
        local pid=$(get_pid)
        log_warn "Already running (PID: $pid)"
        return 1
    fi

    check_prerequisites || return 1

    # Start in daemon mode with nohup
    nohup $PYTHON_BIN "$COLLECTOR_SCRIPT" \
        --config "$CONFIG_FILE" \
        --daemon \
        --interval $INTERVAL \
        >> "$LOG_FILE" 2>&1 &

    local pid=$!
    echo $pid > "$PID_FILE"

    sleep 2

    if is_running; then
        log_msg "Started successfully (PID: $pid)"
        return 0
    else
        log_error "Failed to start - check log: $LOG_FILE"
        rm -f "$PID_FILE"
        return 1
    fi
}

do_stop() {
    log_msg "Stopping Skynet OTX Collector..."

    if ! is_running; then
        log_warn "Not running"
        rm -f "$PID_FILE"
        return 0
    fi

    local pid=$(get_pid)
    kill "$pid" 2>/dev/null

    # Wait for graceful shutdown
    local count=0
    while is_running && [ $count -lt 10 ]; do
        sleep 1
        count=$((count + 1))
    done

    if is_running; then
        log_warn "Forcefully killing process..."
        kill -9 "$pid" 2>/dev/null
    fi

    rm -f "$PID_FILE"
    log_msg "Stopped"
    return 0
}

do_restart() {
    do_stop
    sleep 2
    do_start
}

do_run() {
    log_msg "Running Skynet OTX Collector (single run)..."
    check_prerequisites || return 1

    $PYTHON_BIN "$COLLECTOR_SCRIPT" --config "$CONFIG_FILE"
}

do_status() {
    if is_running; then
        local pid=$(get_pid)
        log_msg "Running (PID: $pid)"

        # Show last few log entries
        if [ -f "$LOG_FILE" ]; then
            echo ""
            echo "Recent log entries:"
            tail -10 "$LOG_FILE"
        fi
        return 0
    else
        log_warn "Not running"
        return 1
    fi
}

do_install() {
    log_msg "Installing Skynet OTX Collector to cron..."

    # Check if cru (Merlin cron utility) is available
    if command -v cru >/dev/null 2>&1; then
        # Remove existing entry
        cru d SkynetOTX 2>/dev/null

        # Add new cron job - run every 5 minutes
        cru a SkynetOTX "*/5 * * * * ${SCRIPT_DIR}/skynet_otx_runner.sh run"

        log_msg "Added to cron (runs every 5 minutes)"
        log_msg "View cron jobs with: cru l"
    else
        # Fallback to direct crontab manipulation
        local cron_entry="*/5 * * * * ${SCRIPT_DIR}/skynet_otx_runner.sh run"

        # Check if already installed
        if crontab -l 2>/dev/null | grep -q "skynet_otx_runner"; then
            log_warn "Already installed in crontab"
            return 0
        fi

        # Add to crontab
        (crontab -l 2>/dev/null; echo "$cron_entry") | crontab -

        log_msg "Added to crontab"
    fi

    # Also add to services-start for persistence across reboots
    local services_script="/jffs/scripts/services-start"

    if [ -f "$services_script" ]; then
        if ! grep -q "skynet_otx_runner" "$services_script"; then
            echo "" >> "$services_script"
            echo "# Skynet OTX Threat Collector" >> "$services_script"
            echo "${SCRIPT_DIR}/skynet_otx_runner.sh start &" >> "$services_script"
            log_msg "Added to $services_script"
        else
            log_warn "Already in $services_script"
        fi
    else
        log_warn "$services_script not found - create it for boot persistence"
    fi

    return 0
}

do_uninstall() {
    log_msg "Uninstalling Skynet OTX Collector from cron..."

    # Stop if running
    do_stop

    # Remove from cru
    if command -v cru >/dev/null 2>&1; then
        cru d SkynetOTX 2>/dev/null
        log_msg "Removed from cru"
    fi

    # Remove from crontab
    if crontab -l 2>/dev/null | grep -q "skynet_otx_runner"; then
        crontab -l 2>/dev/null | grep -v "skynet_otx_runner" | crontab -
        log_msg "Removed from crontab"
    fi

    # Remove from services-start
    local services_script="/jffs/scripts/services-start"
    if [ -f "$services_script" ] && grep -q "skynet_otx_runner" "$services_script"; then
        sed -i '/skynet_otx_runner/d' "$services_script"
        sed -i '/Skynet OTX Threat Collector/d' "$services_script"
        log_msg "Removed from $services_script"
    fi

    log_msg "Uninstalled"
    return 0
}

do_test() {
    log_msg "Testing connections..."
    check_prerequisites || return 1

    echo ""
    echo "Testing Splunk HEC..."
    $PYTHON_BIN "$COLLECTOR_SCRIPT" --config "$CONFIG_FILE" --test-splunk

    echo ""
    echo "Testing OTX API..."
    $PYTHON_BIN "$COLLECTOR_SCRIPT" --config "$CONFIG_FILE" --test-otx
}

show_help() {
    echo "Skynet OTX Threat Collector for Splunk ES"
    echo ""
    echo "Usage: $0 {start|stop|restart|run|status|install|uninstall|test|help}"
    echo ""
    echo "Commands:"
    echo "  start     - Start the collector daemon"
    echo "  stop      - Stop the collector daemon"
    echo "  restart   - Restart the collector daemon"
    echo "  run       - Run collector once (for cron)"
    echo "  status    - Show daemon status"
    echo "  install   - Install to cron and services-start"
    echo "  uninstall - Remove from cron and services-start"
    echo "  test      - Test Splunk HEC and OTX API connectivity"
    echo "  help      - Show this help message"
    echo ""
    echo "Files:"
    echo "  Script:  $COLLECTOR_SCRIPT"
    echo "  Config:  $CONFIG_FILE"
    echo "  Log:     $LOG_FILE"
    echo "  PID:     $PID_FILE"
}

#######################################################################
# Main Entry Point
#######################################################################

case "$1" in
    start)
        do_start
        ;;
    stop)
        do_stop
        ;;
    restart)
        do_restart
        ;;
    run)
        do_run
        ;;
    status)
        do_status
        ;;
    install)
        do_install
        ;;
    uninstall)
        do_uninstall
        ;;
    test)
        do_test
        ;;
    help|--help|-h)
        show_help
        ;;
    *)
        show_help
        exit 1
        ;;
esac

exit $?
