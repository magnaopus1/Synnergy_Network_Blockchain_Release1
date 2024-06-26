#!/bin/bash

# Script to start the Optimization Node
# This script initializes and starts the Optimization Node,
# ensures necessary services are running, and logs the process.

NODE_NAME="OptimizationNode"
PID_FILE="/var/run/${NODE_NAME}.pid"
LOG_FILE="/var/log/${NODE_NAME}.log"
CONFIG_FILE="/etc/${NODE_NAME}/config.toml"
DATA_DIR="/var/lib/${NODE_NAME}"
ENV_FILE="/etc/${NODE_NAME}/.env"

# Function to check if the node is already running
check_if_running() {
    if [ -f "$PID_FILE" ]; then
        PID=$(cat "$PID_FILE")
        if kill -0 "$PID" > /dev/null 2>&1; then
            echo "${NODE_NAME} is already running with PID ${PID}."
            exit 1
        else
            echo "Found stale PID file. Cleaning up..."
            rm -f "$PID_FILE"
        fi
    fi
}

# Function to initialize necessary services
initialize_services() {
    echo "Initializing necessary services for ${NODE_NAME}..."
    
    # Example: Start a dependent service
    # systemctl start some-service
    
    echo "Services initialized."
}

# Function to start the node
start_node() {
    echo "Starting ${NODE_NAME}..."
    
    # Ensure the configuration file exists
    if [ ! -f "$CONFIG_FILE" ]; then
        echo "Configuration file ${CONFIG_FILE} not found!"
        exit 1
    fi

    # Ensure the environment file exists and source it
    if [ -f "$ENV_FILE" ]; then
        source "$ENV_FILE"
    else
        echo "Environment file ${ENV_FILE} not found!"
        exit 1
    fi

    # Start the node process (this is a placeholder, replace with actual command)
    ./node --config "$CONFIG_FILE" --data-dir "$DATA_DIR" >> "$LOG_FILE" 2>&1 &
    
    # Capture the PID and write to the PID file
    echo $! > "$PID_FILE"

    echo "${NODE_NAME} started with PID $(cat $PID_FILE)."
}

# Function to verify the node is running
verify_node() {
    PID=$(cat "$PID_FILE")
    if kill -0 "$PID" > /dev/null 2>&1; then
        echo "${NODE_NAME} is running successfully."
    else
        echo "Failed to start ${NODE_NAME}. Please check the log at ${LOG_FILE}."
        exit 1
    fi
}

# Function to handle errors and ensure safe exit
handle_error() {
    echo "An error occurred. Performing safe exit."
    rm -f "$PID_FILE"
    exit 1
}

# Main script execution
echo "Initializing ${NODE_NAME} start process..."

# Trap errors to ensure safe exit
trap 'handle_error' ERR

# Step-by-step execution
check_if_running
initialize_services
start_node
verify_node

echo "${NODE_NAME} started and verified successfully."

exit 0
