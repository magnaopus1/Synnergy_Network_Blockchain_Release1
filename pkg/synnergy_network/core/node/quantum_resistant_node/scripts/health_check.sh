#!/bin/bash

# Script to perform a health check on the Quantum-Resistant Node

# Function to log messages
log_message() {
    local MESSAGE="$1"
    echo "$(date +'%Y-%m-%d %H:%M:%S') - ${MESSAGE}"
}

# Function to check if the node is running
is_node_running() {
    local NODE_NAME="$1"
    pgrep -f "${NODE_NAME}" > /dev/null 2>&1
    return $?
}

# Function to check the node logs for errors
check_logs_for_errors() {
    local LOG_FILE="./logs/quantum_resistant_node.log"
    if [ -f "${LOG_FILE}" ]; then
        grep -i "error" "${LOG_FILE}" > /dev/null 2>&1
        return $?
    else
        return 1
    fi
}

# Function to check disk space usage
check_disk_space() {
    local THRESHOLD=90
    local USAGE=$(df -h . | awk 'NR==2 {print $5}' | sed 's/%//')
    if [ "${USAGE}" -ge "${THRESHOLD}" ]; then
        return 1
    else
        return 0
    fi
}

# Function to perform a health check
perform_health_check() {
    local NODE_NAME="quantum_resistant_node"

    log_message "Starting health check for ${NODE_NAME}..."

    if is_node_running "${NODE_NAME}"; then
        log_message "Node ${NODE_NAME} is running."
    else
        log_message "Node ${NODE_NAME} is not running."
        return 1
    fi

    if check_logs_for_errors; then
        log_message "No errors found in logs."
    else
        log_message "Errors found in logs."
        return 1
    fi

    if check_disk_space; then
        log_message "Sufficient disk space available."
    else
        log_message "Disk space usage is above threshold."
        return 1
    fi

    log_message "Health check for ${NODE_NAME} completed successfully."
    return 0
}

# Main script execution
main() {
    perform_health_check
    if [ $? -eq 0 ]; then
        log_message "Node health check passed."
        exit 0
    else
        log_message "Node health check failed."
        exit 1
    fi
}

# Execute the main function
main
