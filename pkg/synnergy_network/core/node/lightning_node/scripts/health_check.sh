#!/bin/bash

# Health Check Script for Lightning Node

# Constants
NODE_NAME="lightning_node"
LOG_FILE="/var/log/synthron/$NODE_NAME/health_check.log"
CONFIG_FILE="/etc/synthron/$NODE_NAME/config.toml"
EXECUTABLE="/usr/local/bin/$NODE_NAME"
CHECK_INTERVAL=60  # Interval in seconds between health checks

# Functions
log_message() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" >> $LOG_FILE
}

check_process_running() {
    pid=$(pgrep -f $NODE_NAME)
    if [ -z "$pid" ]; then
        return 1
    else
        return 0
    fi
}

check_network_connectivity() {
    if ping -c 1 8.8.8.8 &> /dev/null; then
        return 0
    else
        return 1
    fi
}

check_ports_open() {
    # Define ports to check (Example: 9735 for Lightning Network)
    PORTS=(9735)

    for PORT in "${PORTS[@]}"; do
        if ! nc -zv localhost $PORT &> /dev/null; then
            return 1
        fi
    done
    return 0
}

restart_node() {
    log_message "Restarting $NODE_NAME"
    $EXECUTABLE --config $CONFIG_FILE &
    sleep 5

    # Check if the process restarted successfully
    if check_process_running; then
        log_message "$NODE_NAME restarted successfully"
    else
        log_message "Failed to restart $NODE_NAME"
    fi
}

# Main
log_message "Starting health check for $NODE_NAME"

while true; do
    if ! check_process_running; then
        log_message "Process is not running. Attempting to restart."
        restart_node
    else
        log_message "Process is running"
    fi

    if ! check_network_connectivity; then
        log_message "Network connectivity issue detected"
    else
        log_message "Network connectivity is good"
    fi

    if ! check_ports_open; then
        log_message "One or more required ports are not open"
    else
        log_message "All required ports are open"
    fi

    log_message "Health check completed. Sleeping for $CHECK_INTERVAL seconds."
    sleep $CHECK_INTERVAL
done
