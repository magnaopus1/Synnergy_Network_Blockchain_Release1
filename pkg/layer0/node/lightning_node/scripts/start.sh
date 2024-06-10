#!/bin/bash

# Start Script for Lightning Node

# Constants
NODE_NAME="lightning_node"
LOG_FILE="/var/log/synthron/$NODE_NAME/start.log"
CONFIG_FILE="/etc/synthron/$NODE_NAME/config.toml"
EXECUTABLE="/usr/local/bin/$NODE_NAME"

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

start_node() {
    log_message "Starting $NODE_NAME"
    $EXECUTABLE --config $CONFIG_FILE &
    sleep 5

    # Check if the process started successfully
    if check_process_running; then
        log_message "$NODE_NAME started successfully"
    else
        log_message "Failed to start $NODE_NAME"
        exit 1
    fi
}

# Main
log_message "Attempting to start $NODE_NAME"

# Check if node process is already running
if check_process_running; then
    log_message "$NODE_NAME is already running"
    exit 0
else
    start_node
fi

# Final verification
if check_process_running; then
    log_message "$NODE_NAME is running"
    exit 0
else
    log_message "Failed to start $NODE_NAME"
    exit 1
fi
