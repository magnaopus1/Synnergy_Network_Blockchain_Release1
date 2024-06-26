#!/bin/bash

# AI-Enhanced Node Stop Script
# This script stops the AI-Enhanced Node for the Synthron blockchain.
# Ensure that all operations are completed gracefully and logs are properly stored.

# Load environment variables
source ../.env

# Functions to handle stopping the node and cleaning up resources
stop_node() {
    echo "Stopping AI-Enhanced Node..."

    # Stop the node process
    NODE_PID=$(pgrep -f ai_enhanced_node)
    if [ -z "$NODE_PID" ]; then
        echo "AI-Enhanced Node is not running."
    else
        kill -SIGTERM "$NODE_PID"
        echo "Sent SIGTERM to AI-Enhanced Node process with PID: $NODE_PID"
        
        # Wait for the process to terminate
        while kill -0 "$NODE_PID" >/dev/null 2>&1; do
            echo "Waiting for AI-Enhanced Node to stop..."
            sleep 1
        done
        echo "AI-Enhanced Node stopped successfully."
    fi
}

cleanup() {
    echo "Cleaning up resources..."

    # Ensure all temporary files and logs are properly handled
    TEMP_DIR="../data/temp"
    LOG_DIR="../logs"

    if [ -d "$TEMP_DIR" ]; then
        rm -rf "$TEMP_DIR"
        echo "Removed temporary files from $TEMP_DIR"
    fi

    if [ -d "$LOG_DIR" ]; then
        echo "Log files are stored in $LOG_DIR"
    else
        echo "Log directory does not exist."
    fi
}

save_state() {
    echo "Saving node state..."

    # Save any necessary state information before shutting down
    STATE_DIR="../data/state"
    if [ ! -d "$STATE_DIR" ]; then
        mkdir -p "$STATE_DIR"
    fi

    # Example state saving logic
    echo "Current timestamp: $(date)" > "$STATE_DIR/node_state.txt"
    echo "Node state saved successfully in $STATE_DIR"
}

# Main script execution
echo "Executing stop script for AI-Enhanced Node..."

save_state
stop_node
cleanup

echo "AI-Enhanced Node has been stopped and cleaned up."
