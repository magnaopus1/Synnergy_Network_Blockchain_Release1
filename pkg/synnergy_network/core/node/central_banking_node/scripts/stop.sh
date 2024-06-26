#!/bin/bash

# Setup environment variables
LOG_PATH="/var/log/synthron/central_banking_node.log"

# Define the location of the node application PID file
PID_PATH="/var/run/central_banking_node.pid"

echo "Stopping Central Banking Node..."

# Function to log messages
log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" >> $LOG_PATH
}

# Check if the node is running and stop it
stop_node() {
    if [ -f "$PID_PATH" ]; then
        PID=$(cat "$PID_PATH")
        if ps -p $PID > /dev/null; then
           echo "Shutting down Central Banking Node..."
           kill $PID
           # Wait for the process to be properly terminated
           wait $PID 2>/dev/null
           log "Central Banking Node stopped successfully."
           rm -f "$PID_PATH"
        else
           log "PID file found but no matching process was found. Cleaning up PID file."
           rm -f "$PID_PATH"
        fi
    else
        log "Central Banking Node is not running or PID file is missing."
    fi
}

# Additional cleanup actions, if any
cleanup() {
    log "Performing system cleanup..."
    # Add any additional cleanup tasks here
    echo "Cleanup completed."
}

# Main execution flow
stop_node
cleanup

echo "Central Banking Node shutdown sequence completed."

