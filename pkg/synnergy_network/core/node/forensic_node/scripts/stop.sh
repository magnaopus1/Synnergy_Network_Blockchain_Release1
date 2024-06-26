#!/bin/bash

# Forensic Node stop script
# This script stops the Forensic Node gracefully and performs necessary cleanup.

# Function to stop the Forensic Node
stop_node() {
    NODE_PID=$(pgrep -f forensic_node)
    
    if [ -z "$NODE_PID" ]; then
        echo "Forensic Node is not running."
    else
        echo "Stopping Forensic Node with PID: $NODE_PID"
        kill -SIGTERM "$NODE_PID"
        
        # Wait for the process to terminate
        while kill -0 "$NODE_PID" > /dev/null 2>&1; do
            echo "Waiting for Forensic Node to terminate..."
            sleep 1
        done

        echo "Forensic Node stopped successfully."
    fi
}

# Function to clean up logs and temporary data
cleanup() {
    echo "Cleaning up logs and temporary data..."
    LOG_DIR="./logs"
    DATA_DIR="./data"

    if [ -d "$LOG_DIR" ]; then
        rm -rf "$LOG_DIR"/*
        echo "Logs cleaned up."
    else
        echo "Log directory not found."
    fi

    if [ -d "$DATA_DIR" ]; then
        rm -rf "$DATA_DIR"/*
        echo "Temporary data cleaned up."
    else
        echo "Data directory not found."
    fi
}

# Main function to perform all tasks
main() {
    stop_node
    cleanup
}

# Execute the main function
main
