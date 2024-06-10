#!/bin/bash

# Stop Script for Watchtower Node
# This script stops the Watchtower Node gracefully

NODE_NAME="synthron_watchtower"
PID_FILE="/var/run/${NODE_NAME}.pid"
LOG_FILE="/var/log/${NODE_NAME}/shutdown.log"
ERROR_LOG_FILE="/var/log/${NODE_NAME}/shutdown_error.log"

# Function to log messages
log_message() {
    local message=$1
    echo "$(date +'%Y-%m-%d %H:%M:%S') - ${message}" | tee -a $LOG_FILE
}

# Function to log errors
log_error() {
    local message=$1
    echo "$(date +'%Y-%m-%d %H:%M:%S') - ERROR: ${message}" | tee -a $ERROR_LOG_FILE
}

# Function to stop the Watchtower Node
stop_node() {
    if [ -f "$PID_FILE" ]; then
        PID=$(cat "$PID_FILE")
        if ps -p $PID > /dev/null; then
            log_message "Stopping Watchtower Node (PID: $PID)..."
            kill -SIGTERM $PID
            sleep 5
            if ps -p $PID > /dev/null; then
                log_message "Watchtower Node did not stop gracefully, forcing stop (PID: $PID)..."
                kill -SIGKILL $PID
            fi
            rm -f "$PID_FILE"
            log_message "Watchtower Node stopped successfully."
        else
            log_error "PID file found but no process with PID $PID is running."
            rm -f "$PID_FILE"
        fi
    else
        log_error "No PID file found. Is the Watchtower Node running?"
    fi
}

# Ensure log directories exist
mkdir -p "$(dirname "$LOG_FILE")"
mkdir -p "$(dirname "$ERROR_LOG_FILE")"

# Main execution
log_message "Initiating Watchtower Node shutdown process."
stop_node
log_message "Shutdown process completed."

exit 0
