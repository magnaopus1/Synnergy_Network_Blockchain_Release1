#!/bin/bash

# AI-Enhanced Node Start Script
# This script starts the AI-Enhanced Node for the Synthron blockchain.
# Ensure that all prerequisites are met and the node starts correctly.

# Load environment variables
source ../.env

# Functions to handle starting the node
start_node() {
    echo "Starting AI-Enhanced Node..."

    # Define the path to the node executable
    NODE_EXECUTABLE="../node/ai_enhanced_node"

    # Check if the node executable exists
    if [ ! -f "$NODE_EXECUTABLE" ]; then
        echo "Error: AI-Enhanced Node executable not found at $NODE_EXECUTABLE"
        exit 1
    fi

    # Start the node process
    nohup "$NODE_EXECUTABLE" > ../logs/ai_enhanced_node.log 2>&1 &

    NODE_PID=$!
    echo "AI-Enhanced Node started with PID: $NODE_PID"
}

initialize_logging() {
    echo "Initializing logging..."

    LOG_DIR="../logs"
    if [ ! -d "$LOG_DIR" ]; then
        mkdir -p "$LOG_DIR"
    fi

    echo "Logs will be stored in $LOG_DIR"
}

verify_startup() {
    echo "Verifying AI-Enhanced Node startup..."

    # Wait for a few seconds to ensure the node has started
    sleep 5

    # Check if the node is running
    if ps -p $NODE_PID > /dev/null; then
        echo "AI-Enhanced Node is running successfully."
    else
        echo "Error: AI-Enhanced Node failed to start."
        exit 1
    fi
}

# Main script execution
echo "Executing start script for AI-Enhanced Node..."

initialize_logging
start_node
verify_startup

echo "AI-Enhanced Node has been started successfully."
