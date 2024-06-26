#!/bin/bash

# Stop the Synthron Hybrid Node

# Function to check if the process is running
is_running() {
    local pid=$1
    if [ -d "/proc/$pid" ]; then
        return 0
    else
        return 1
    fi
}

# Function to gracefully stop the node
stop_node() {
    local pid=$1
    echo "Stopping Hybrid Node (PID: $pid)..."
    kill -SIGTERM "$pid"

    # Wait for the process to exit
    local timeout=30
    while [ $timeout -gt 0 ]; do
        if ! is_running "$pid"; then
            echo "Hybrid Node stopped successfully."
            return 0
        fi
        sleep 1
        timeout=$((timeout - 1))
    done

    # Force kill if not stopped gracefully
    echo "Hybrid Node did not stop gracefully, forcing termination..."
    kill -SIGKILL "$pid"

    # Check if the process is still running
    if is_running "$pid"; then
        echo "Failed to stop Hybrid Node (PID: $pid). Please check manually."
        return 1
    else
        echo "Hybrid Node stopped successfully."
        return 0
    fi
}

# Main script execution
HYBRID_NODE_PID_FILE="/var/run/synthron/hybrid_node.pid"

if [ ! -f "$HYBRID_NODE_PID_FILE" ]; then
    echo "Hybrid Node PID file not found. Is the Hybrid Node running?"
    exit 1
fi

HYBRID_NODE_PID=$(cat "$HYBRID_NODE_PID_FILE")

if is_running "$HYBRID_NODE_PID"; then
    stop_node "$HYBRID_NODE_PID"
    rm -f "$HYBRID_NODE_PID_FILE"
else
    echo "Hybrid Node (PID: $HYBRID_NODE_PID) is not running."
    rm -f "$HYBRID_NODE_PID_FILE"
fi
