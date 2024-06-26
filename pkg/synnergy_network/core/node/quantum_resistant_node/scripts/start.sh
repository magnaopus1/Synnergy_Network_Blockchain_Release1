#!/bin/bash

# Script to start the Quantum-Resistant Node

# Function to log messages
log_message() {
    local MESSAGE="$1"
    echo "$(date +'%Y-%m-%d %H:%M:%S') - ${MESSAGE}"
}

# Function to check if the node is already running
is_node_running() {
    local NODE_NAME="$1"
    pgrep -f "${NODE_NAME}" > /dev/null 2>&1
}

# Function to start the node
start_node() {
    local NODE_NAME="$1"
    local NODE_EXECUTABLE="./${NODE_NAME}"
    local CONFIG_FILE="./config.toml"

    if is_node_running "${NODE_NAME}"; then
        log_message "Node ${NODE_NAME} is already running."
        return 1
    fi

    if [ ! -f "${NODE_EXECUTABLE}" ]; then
        log_message "Node executable ${NODE_EXECUTABLE} not found."
        return 1
    fi

    if [ ! -f "${CONFIG_FILE}" ]; then
        log_message "Config file ${CONFIG_FILE} not found."
        return 1
    fi

    log_message "Starting ${NODE_NAME}..."
    nohup "${NODE_EXECUTABLE}" --config "${CONFIG_FILE}" > "./logs/${NODE_NAME}.log" 2>&1 &
    local NODE_PID=$!
    log_message "${NODE_NAME} started with PID ${NODE_PID}."

    return 0
}

# Function to setup necessary directories and files
setup_environment() {
    mkdir -p ./logs
    mkdir -p ./data
    log_message "Environment setup completed."
}

# Main script execution
main() {
    NODE_NAME="quantum_resistant_node"

    setup_environment

    log_message "Attempting to start ${NODE_NAME}..."
    start_node "${NODE_NAME}"

    if [ $? -eq 0 ]; then
        log_message "${NODE_NAME} started successfully."
    else
        log_message "Failed to start ${NODE_NAME}."
        exit 1
    fi

    log_message "Start script completed."
}

# Execute the main function
main
