#!/bin/bash

# Stop Script for Lightning Node

# Constants
NODE_NAME="lightning_node"
LOG_FILE="/var/log/synthron/$NODE_NAME/stop.log"

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

stop_node() {
    pid=$(pgrep -f $NODE_NAME)
    if [ -n "$pid" ]; then
        kill -SIGTERM $pid
        log_message "Sent SIGTERM to process $pid"
        sleep 5

        # Check if process is still running
        if check_process_running; then
            log_message "Process $pid did not terminate, sending SIGKILL"
            kill -SIGKILL $pid
        else
            log_message "Process $pid terminated successfully"
        fi
    else
        log_message "No running $NODE_NAME process found"
    fi
}

# Main
log_message "Attempting to stop $NODE_NAME"

# Check if node process is running
if check_process_running; then
    stop_node
else
    log_message "No $NODE_NAME process running"
fi

# Final verification
if check_process_running; then
    log_message "Failed to stop $NODE_NAME process"
    exit 1
else
    log_message "$NODE_NAME stopped successfully"
    exit 0
fi
