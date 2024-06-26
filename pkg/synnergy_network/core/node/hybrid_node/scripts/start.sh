#!/bin/bash

# Start the Synthron Hybrid Node

# Set environment variables if necessary
export NODE_ENV="production"
export LOG_LEVEL="info"

# Function to check if the node is already running
is_running() {
    local pid=$1
    if [ -d "/proc/$pid" ]; then
        return 0
    else
        return 1
    fi
}

# Function to start the node
start_node() {
    local config_file="/etc/synthron/hybrid_node/config.toml"
    local log_file="/var/log/synthron/hybrid_node.log"

    echo "Starting Hybrid Node with configuration file: $config_file"
    /usr/local/bin/synthron-hybrid-node --config "$config_file" >> "$log_file" 2>&1 &
    local pid=$!
    echo $pid > /var/run/synthron/hybrid_node.pid
    echo "Hybrid Node started with PID: $pid"
}

# Main script execution
HYBRID_NODE_PID_FILE="/var/run/synthron/hybrid_node.pid"

if [ -f "$HYBRID_NODE_PID_FILE" ]; then
    HYBRID_NODE_PID=$(cat "$HYBRID_NODE_PID_FILE")
    if is_running "$HYBRID_NODE_PID"; then
        echo "Hybrid Node is already running with PID: $HYBRID_NODE_PID"
        exit 0
    else
        echo "Stale PID file found. Removing..."
        rm -f "$HYBRID_NODE_PID_FILE"
    fi
fi

start_node
