#!/bin/bash

# Staking Node Start Script
# This script starts the staking node in the Synthron blockchain network.

# Function to log information with timestamp
log_info() {
    echo "$(date +'%Y-%m-%d %H:%M:%S') [INFO] $1"
}

# Function to log error with timestamp
log_error() {
    echo "$(date +'%Y-%m-%d %H:%M:%S') [ERROR] $1"
}

# Function to start the staking node process
start_staking_node() {
    local NODE_NAME="synthron_staking_node"
    local NODE_EXECUTABLE="./node"
    local CONFIG_FILE="./config.toml"

    log_info "Starting the staking node..."

    # Check if the executable exists
    if [ ! -f "$NODE_EXECUTABLE" ]; then
        log_error "Node executable not found: $NODE_EXECUTABLE"
        return 1
    fi

    # Check if the configuration file exists
    if [ ! -f "$CONFIG_FILE" ]; then
        log_error "Configuration file not found: $CONFIG_FILE"
        return 1
    fi

    # Start the staking node process
    nohup "$NODE_EXECUTABLE" --config "$CONFIG_FILE" > ./logs/staking_node.log 2>&1 &
    if [ $? -ne 0 ]; then
        log_error "Failed to start the staking node process."
        return 1
    fi

    # Verify the process started
    sleep 2
    NODE_PID=$(pgrep -f "$NODE_NAME")
    if [ -z "$NODE_PID" ]; then
        log_error "Staking node process did not start."
        return 1
    fi

    log_info "Staking node started successfully with PID: $NODE_PID"
    return 0
}

# Function to initialize necessary directories and files
initialize_directories() {
    log_info "Initializing directories and files..."

    mkdir -p ./data
    mkdir -p ./logs

    log_info "Initialization completed."
}

# Main function
main() {
    initialize_directories

    start_staking_node
    if [ $? -ne 0 ]; then
        log_error "Failed to start the staking node."
        exit 1
    fi

    log_info "Staking node has been started successfully."
    exit 0
}

# Execute the main function
main
