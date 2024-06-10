#!/bin/bash

# Synthron Master Node Stop Script
# This script stops the Synthron Master Node safely and efficiently.

# Function to print messages
log_message() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $1"
}

# Function to stop the Master Node
stop_master_node() {
    log_message "Stopping Synthron Master Node..."

    # Check if the node process is running
    NODE_PID=$(pgrep -f "synthron_master_node")
    if [ -z "$NODE_PID" ]; then
        log_message "Master Node is not running."
        exit 1
    fi

    # Send a termination signal to the Master Node process
    log_message "Sending termination signal to Master Node (PID: $NODE_PID)..."
    kill -SIGTERM "$NODE_PID"

    # Wait for the process to terminate
    TIMEOUT=30
    while kill -0 "$NODE_PID" 2>/dev/null; do
        TIMEOUT=$((TIMEOUT - 1))
        if [ "$TIMEOUT" -le 0 ]; then
            log_message "Master Node did not terminate in time, sending SIGKILL..."
            kill -SIGKILL "$NODE_PID"
            break
        fi
        sleep 1
    done

    log_message "Master Node stopped successfully."
}

# Function to clean up resources
cleanup_resources() {
    log_message "Cleaning up resources..."

    # Remove lock files or temporary data
    LOCK_FILE="/var/lock/synthron_master_node.lock"
    if [ -f "$LOCK_FILE" ]; then
        rm -f "$LOCK_FILE"
        log_message "Removed lock file: $LOCK_FILE"
    fi

    # Optional: Additional cleanup steps
    # Example: Removing temporary files
    TEMP_DIR="/tmp/synthron_master_node"
    if [ -d "$TEMP_DIR" ]; then
        rm -rf "$TEMP_DIR"
        log_message "Removed temporary directory: $TEMP_DIR"
    fi

    log_message "Resource cleanup completed."
}

# Function to ensure the log directory exists
ensure_log_directory() {
    LOG_DIR="/var/log/synthron"
    if [ ! -d "$LOG_DIR" ]; then
        mkdir -p "$LOG_DIR"
        log_message "Created log directory: $LOG_DIR"
    fi
}

# Ensure the log directory exists
ensure_log_directory

# Start stopping the node
stop_master_node

# Clean up resources
cleanup_resources

log_message "Synthron Master Node has been stopped."
