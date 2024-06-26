#!/bin/bash

# Start Script for Watchtower Node
# This script starts the Watchtower Node with all necessary configurations

NODE_NAME="synthron_watchtower"
PID_FILE="/var/run/${NODE_NAME}.pid"
LOG_FILE="/var/log/${NODE_NAME}/startup.log"
ERROR_LOG_FILE="/var/log/${NODE_NAME}/startup_error.log"
CONFIG_FILE="/path/to/your/config.toml"  # Adjust this path as necessary
EXECUTABLE="/usr/local/bin/watchtower_node"  # Adjust this path as necessary

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

# Function to start the Watchtower Node
start_node() {
    if [ -f "$PID_FILE" ]; then
        PID=$(cat "$PID_FILE")
        if ps -p $PID > /dev/null; then
            log_message "Watchtower Node is already running with PID: $PID"
            exit 0
        else
            log_error "PID file exists but no process with PID $PID is running. Cleaning up."
            rm -f "$PID_FILE"
        fi
    fi

    log_message "Starting Watchtower Node..."
    $EXECUTABLE --config $CONFIG_FILE &

    if [ $? -eq 0 ]; then
        echo $! > "$PID_FILE"
        log_message "Watchtower Node started successfully with PID: $(cat $PID_FILE)"
    else
        log_error "Failed to start Watchtower Node."
        exit 1
    fi
}

# Ensure log directories exist
mkdir -p "$(dirname "$LOG_FILE")"
mkdir -p "$(dirname "$ERROR_LOG_FILE")"

# Main execution
log_message "Initiating Watchtower Node startup process."
start_node
log_message "Startup process completed."

exit 0
