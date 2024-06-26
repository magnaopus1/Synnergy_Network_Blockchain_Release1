#!/bin/bash

# Script to stop the Quantum-Resistant Node

# Function to log messages
log_message() {
    local MESSAGE="$1"
    echo "$(date +'%Y-%m-%d %H:%M:%S') - ${MESSAGE}"
}

# Function to stop the node
stop_node() {
    local NODE_NAME="$1"

    # Check if the node process is running
    local NODE_PID
    NODE_PID=$(pgrep -f "${NODE_NAME}")

    if [ -z "${NODE_PID}" ]; then
        log_message "Node ${NODE_NAME} is not running."
        return 1
    fi

    # Stop the node process
    kill -SIGTERM "${NODE_PID}"
    log_message "Sent SIGTERM to ${NODE_NAME} (PID: ${NODE_PID})."

    # Wait for the process to terminate
    sleep 5

    # Check if the process is still running and forcefully kill if necessary
    if ps -p "${NODE_PID}" > /dev/null; then
        kill -SIGKILL "${NODE_PID}"
        log_message "Forcefully killed ${NODE_NAME} (PID: ${NODE_PID})."
    else
        log_message "${NODE_NAME} stopped gracefully."
    fi
}

# Main script execution
main() {
    NODE_NAME="quantum_resistant_node"

    log_message "Attempting to stop ${NODE_NAME}..."
    stop_node "${NODE_NAME}"

    if [ $? -eq 0 ]; then
        log_message "${NODE_NAME} stopped successfully."
    else
        log_message "Failed to stop ${NODE_NAME}."
        exit 1
    fi

    log_message "Cleanup operations..."
    # Perform any necessary cleanup operations here

    log_message "Stop script completed."
}

# Execute the main function
main
