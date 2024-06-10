#!/bin/bash

# stop.sh - Script to gracefully stop the Consensus-Specific Node

# Define the node identifier for logging
NODE_ID="Consensus-Specific Node"

# Log file location
LOG_FILE="/var/log/synthron/consensus_specific_node/stop.log"

# Function to log messages with timestamps
log_message() {
    local MESSAGE="$1"
    echo "$(date '+%Y-%m-%d %H:%M:%S') - ${NODE_ID} - ${MESSAGE}" | tee -a "$LOG_FILE"
}

# Check if the node process ID file exists
PID_FILE="/var/run/synthron/consensus_specific_node.pid"

if [ ! -f "$PID_FILE" ]; then
    log_message "No PID file found. The node may not be running."
    exit 1
fi

# Read the PID from the file
NODE_PID=$(cat "$PID_FILE")

# Function to stop the node gracefully
stop_node() {
    log_message "Stopping the node with PID $NODE_PID..."
    kill -SIGTERM "$NODE_PID"

    # Wait for the node to terminate
    WAIT_TIME=30
    while [ $WAIT_TIME -gt 0 ]; do
        if ps -p "$NODE_PID" > /dev/null; then
            sleep 1
            WAIT_TIME=$((WAIT_TIME - 1))
        else
            log_message "Node stopped successfully."
            rm -f "$PID_FILE"
            exit 0
        fi
    done

    # If the node is still running, forcefully kill it
    if ps -p "$NODE_PID" > /dev/null; then
        log_message "Node did not stop within the timeout. Forcing termination..."
        kill -SIGKILL "$NODE_PID"
        rm -f "$PID_FILE"
        log_message "Node forcefully terminated."
    else
        rm -f "$PID_FILE"
        log_message "Node stopped successfully."
    fi
}

# Check if the node process is running
if ps -p "$NODE_PID" > /dev/null; then
    stop_node
else
    log_message "Node with PID $NODE_PID is not running."
    rm -f "$PID_FILE"
    exit 1
fi
