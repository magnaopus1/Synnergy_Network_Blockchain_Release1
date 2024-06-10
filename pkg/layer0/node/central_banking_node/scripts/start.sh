#!/bin/bash

# Setup environment variables
export NODE_ENV=production
export LOG_PATH=/var/log/synthron/central_banking_node.log

# Define the location of the node application executable
NODE_BIN="/usr/local/bin/central_banking_node"

# Location of the configuration file
CONFIG_FILE="/etc/synthron/central_banking_node_config.toml"

echo "Starting Central Banking Node..."

# Function to check the existence of the configuration file
check_config() {
    if [ ! -f "$CONFIG_FILE" ]; then
        echo "Configuration file not found: $CONFIG_FILE"
        exit 1
    else
        echo "Configuration file is found and will be used."
    fi
}

# Start the Central Banking Node
start_node() {
    # Check if the node application binary exists
    if [ -x "$NODE_BIN" ]; then
        echo "Launching the Central Banking Node..."
        # Redirect logs to a file specified by LOG_PATH
        "$NODE_BIN" >> "$LOG_PATH" 2>&1 &
        echo "Central Banking Node started successfully."
    else
        echo "Executable binary for node not found: $NODE_BIN"
        exit 1
    fi
}

# Main execution flow
check_config
start_node

# Optional: Add a health check loop or post-start checks
echo "Performing initial health checks..."
sleep 10  # Wait for the application to start
# Implement a basic health check by pinging the node's API or checking process status
if pgrep -x "central_banking_node" >/dev/null
then
    echo "Health check passed. Node is running."
else
    echo "Health check failed. Node is not running."
    exit 1
fi

