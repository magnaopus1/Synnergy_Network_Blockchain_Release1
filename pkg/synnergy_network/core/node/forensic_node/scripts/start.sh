#!/bin/bash

# Forensic Node start script
# This script starts the Forensic Node and ensures all necessary services and dependencies are running.

# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to start the Forensic Node
start_node() {
    # Check if the forensic node binary exists
    if [ ! -f "./forensic_node" ]; then
        echo "Forensic Node binary not found. Please ensure the binary is in the current directory."
        exit 1
    fi

    # Start the Forensic Node
    echo "Starting Forensic Node..."
    nohup ./forensic_node > logs/forensic_node.log 2>&1 &

    # Get the PID of the started process
    NODE_PID=$!
    echo "Forensic Node started with PID: $NODE_PID"
}

# Function to ensure necessary services are running
ensure_services() {
    echo "Checking necessary services..."

    # Example: Check if Docker is installed and running (if required by your setup)
    if command_exists docker; then
        if ! pgrep -x "docker" > /dev/null; then
            echo "Docker is not running. Starting Docker..."
            sudo service docker start
        fi
    fi

    # Example: Check if any other required service is running
    # Add checks for other services as required by your setup
}

# Function to ensure necessary directories exist
ensure_directories() {
    echo "Ensuring necessary directories exist..."
    mkdir -p ./logs
    mkdir -p ./data
}

# Main function to perform all startup tasks
main() {
    ensure_directories
    ensure_services
    start_node
}

# Execute the main function
main
