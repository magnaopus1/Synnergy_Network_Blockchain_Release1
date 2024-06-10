#!/bin/bash

# Synthron Blockchain - Archival Full Node Stop Script
# This script safely stops the Archival Full Node.

# Configuration Variables
NODE_DIR="/path/to/your/node"
CONFIG_FILE="$NODE_DIR/config.toml"
LOG_FILE="$NODE_DIR/node.log"
NODE_BINARY="/usr/local/bin/synthron_node"
NODE_PID_FILE="$NODE_DIR/node.pid"
BACKUP_DIR="$NODE_DIR/backup"
BACKUP_TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# Function to check if the node is running
check_node_running() {
    echo "Checking if the node is running..."
    if [ ! -f "$NODE_PID_FILE" ]; then
        echo "Node PID file not found. Is the node running?" >&2
        exit 1
    fi

    NODE_PID=$(cat "$NODE_PID_FILE")
    if ! ps -p "$NODE_PID" > /dev/null; then
        echo "Node process not found. It might not be running." >&2
        exit 1
    fi
    echo "Node is running with PID $NODE_PID."
}

# Function to stop the node
stop_node() {
    echo "Stopping the node..."
    kill -SIGTERM "$NODE_PID"

    # Wait for the node to shut down gracefully
    sleep 5

    if ps -p "$NODE_PID" > /dev/null; then
        echo "Node did not shut down gracefully, forcing shutdown..."
        kill -SIGKILL "$NODE_PID"
    fi

    # Remove the PID file after stopping the node
    rm -f "$NODE_PID_FILE"
    echo "Node stopped successfully."
}

# Function to backup node data
backup_node_data() {
    echo "Backing up node data..."
    mkdir -p "$BACKUP_DIR"
    tar -czf "$BACKUP_DIR/node_backup_$BACKUP_TIMESTAMP.tar.gz" -C "$NODE_DIR" .
    echo "Node data backed up to $BACKUP_DIR/node_backup_$BACKUP_TIMESTAMP.tar.gz."
}

# Function to clean up resources
cleanup_resources() {
    echo "Cleaning up resources..."
    # Add any additional cleanup steps if necessary
    echo "Resources cleaned up."
}

# Function to disable monitoring tools
disable_monitoring() {
    echo "Disabling monitoring tools..."
    # Placeholder for actual monitoring tools shutdown, e.g., Prometheus, Grafana
    echo "Monitoring tools disabled."
}

# Function to disable secure communication
disable_secure_communication() {
    echo "Disabling secure communication..."
    # Ensure that TLS and authentication settings are correctly handled
    # Placeholder for any secure communication teardown steps
    echo "Secure communication disabled."
}

# Main function to stop the archival full node
main() {
    check_node_running
    stop_node
    backup_node_data
    cleanup_resources
    disable_monitoring
    disable_secure_communication
    echo "Archival Full Node stopped successfully."
}

# Run the main function
main
