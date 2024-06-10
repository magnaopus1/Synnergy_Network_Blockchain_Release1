#!/bin/bash

# Orphan Node Start Script
# This script starts the Orphan Node, ensuring all necessary services are up and running.

# Configuration
CONFIG_PATH="/etc/orphan_node/config.toml"
LOG_FILE="/var/log/orphan_node/orphan_node.log"
NODE_BINARY="/usr/local/bin/orphan_node"

# Load configuration
if [ -f $CONFIG_PATH ]; then
    source $CONFIG_PATH
else
    echo "Configuration file not found at $CONFIG_PATH"
    exit 1
fi

# Function to check if a process is running
is_running() {
    pgrep -f $NODE_BINARY > /dev/null 2>&1
}

# Function to start the Orphan Node process
start_orphan_node() {
    echo "Starting Orphan Node..."

    if is_running; then
        echo "Orphan Node is already running."
        exit 0
    fi

    # Start the Orphan Node process
    nohup $NODE_BINARY --config $CONFIG_PATH >> $LOG_FILE 2>&1 &
    NODE_PID=$!

    echo "Orphan Node started with PID: $NODE_PID"
}

# Function to check network connectivity
check_network() {
    echo "Checking network connectivity..."
    if ping -c 1 google.com &> /dev/null; then
        echo "Network connectivity is active."
    else
        echo "Network connectivity is down. Exiting..."
        exit 1
    fi
}

# Function to initialize monitoring tools
initialize_monitoring() {
    echo "Initializing monitoring tools..."
    # Add any monitoring initialization commands here
    echo "Monitoring tools initialized."
}

# Function to log the starting process
log_start_process() {
    echo "Logging start process to $LOG_FILE"
    {
        echo "======================="
        echo "Orphan Node Start Script"
        echo "======================="
        echo "Timestamp: $(date)"
        echo "Starting Orphan Node..."
    } >> $LOG_FILE

    if [ $? -eq 0 ]; then
        echo "Start process logged successfully."
    else
        echo "Failed to log start process."
    fi
}

# Main
log_start_process
check_network
initialize_monitoring
start_orphan_node

echo "Orphan Node has been started."
