#!/bin/bash

# Staking Node Stop Script
# This script stops the staking node in the Synthron blockchain network.

# Function to log information with timestamp
log_info() {
    echo "$(date +'%Y-%m-%d %H:%M:%S') [INFO] $1"
}

# Function to log error with timestamp
log_error() {
    echo "$(date +'%Y-%m-%d %H:%M:%S') [ERROR] $1"
}

# Function to stop the staking node process
stop_staking_node() {
    local NODE_NAME="synthron_staking_node"
    
    log_info "Stopping the staking node..."

    # Check if the staking node process is running
    NODE_PID=$(pgrep -f "$NODE_NAME")
    if [ -z "$NODE_PID" ]; then
        log_error "Staking node is not running."
        return 1
    fi

    # Attempt to stop the process
    kill "$NODE_PID"
    if [ $? -ne 0 ]; then
        log_error "Failed to stop the staking node process."
        return 1
    fi

    # Wait for the process to terminate
    sleep 5

    # Verify that the process has been terminated
    NODE_PID=$(pgrep -f "$NODE_NAME")
    if [ -n "$NODE_PID" ]; then
        log_error "Staking node process did not terminate. Force killing..."
        kill -9 "$NODE_PID"
        if [ $? -ne 0 ]; then
            log_error "Failed to force kill the staking node process."
            return 1
        fi
    fi

    log_info "Staking node stopped successfully."
    return 0
}

# Function to clean up resources
cleanup() {
    log_info "Cleaning up resources..."

    # Perform any necessary cleanup operations here
    # For example, removing temporary files, closing open connections, etc.

    log_info "Cleanup completed."
}

# Main function
main() {
    stop_staking_node
    if [ $? -ne 0 ]; then
        log_error "Failed to stop the staking node."
        exit 1
    fi

    cleanup
    log_info "Staking node has been stopped and cleaned up successfully."
    exit 0
}

# Execute the main function
main
