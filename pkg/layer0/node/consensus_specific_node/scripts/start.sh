#!/bin/bash

# start.sh - Script to start the Consensus-Specific Node

# Define the node identifier for logging
NODE_ID="Consensus-Specific Node"

# Log file location
LOG_FILE="/var/log/synthron/consensus_specific_node/start.log"

# PID file location
PID_FILE="/var/run/synthron/consensus_specific_node.pid"

# Function to log messages with timestamps
log_message() {
    local MESSAGE="$1"
    echo "$(date '+%Y-%m-%d %H:%M:%S') - ${NODE_ID} - ${MESSAGE}" | tee -a "$LOG_FILE"
}

# Function to start the node
start_node() {
    log_message "Starting the Consensus-Specific Node..."

    # Change to the directory where the node binary is located
    cd /path/to/node/binary || { log_message "Failed to change directory"; exit 1; }

    # Start the node in the background and capture its PID
    ./consensus_specific_node > /dev/null 2>&1 &
    NODE_PID=$!
    echo $NODE_PID > "$PID_FILE"

    log_message "Node started with PID $NODE_PID"
}

# Check if the node is already running
if [ -f "$PID_FILE" ]; then
    EXISTING_PID=$(cat "$PID_FILE")
    if ps -p "$EXISTING_PID" > /dev/null; then
        log_message "Node is already running with PID $EXISTING_PID"
        exit 0
    else
        log_message "Found PID file but no running process. Cleaning up stale PID file."
        rm -f "$PID_FILE"
    fi
fi

# Start the node
start_node

# Additional configurations or checks can be added here if needed

log_message "Node startup script completed."
