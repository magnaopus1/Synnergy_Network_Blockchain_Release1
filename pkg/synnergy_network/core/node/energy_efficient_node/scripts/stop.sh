#!/bin/bash

# Stop script for Energy-Efficient Node

# Load environment variables
source /path/to/your/env/file/.env

# Function to stop the node
stop_node() {
    echo "Stopping Energy-Efficient Node..."

    # Check if the node is running
    if pgrep -f "energy_efficient_node" > /dev/null; then
        # Get the process ID
        NODE_PID=$(pgrep -f "energy_efficient_node")

        # Gracefully stop the node process
        kill -SIGTERM "$NODE_PID"

        # Wait for the process to stop
        while kill -0 "$NODE_PID" > /dev/null 2>&1; do
            sleep 1
        done

        echo "Energy-Efficient Node stopped successfully."
    else
        echo "Energy-Efficient Node is not running."
    fi
}

# Function to backup node data before stopping
backup_node_data() {
    echo "Backing up node data..."

    # Define backup directory
    BACKUP_DIR="$BACKUP_DIRECTORY/$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$BACKUP_DIR"

    # Copy data directory to backup location
    cp -r "$DATA_DIRECTORY" "$BACKUP_DIR"

    echo "Node data backed up successfully to $BACKUP_DIR."
}

# Function to monitor energy usage before stopping
monitor_energy_usage() {
    echo "Monitoring energy usage before stopping..."

    # Placeholder for monitoring logic
    # Implement actual energy usage monitoring logic here
    # Example: fetch energy usage data and log it

    ENERGY_USAGE_LOG="$LOG_DIRECTORY/energy_usage_$(date +%Y%m%d_%H%M%S).log"
    echo "Energy usage data..." > "$ENERGY_USAGE_LOG"

    echo "Energy usage monitored and logged to $ENERGY_USAGE_LOG."
}

# Perform pre-stop actions
monitor_energy_usage
backup_node_data

# Stop the node
stop_node

# Perform any post-stop cleanup if necessary
echo "Post-stop cleanup completed."

# Exit script
exit 0
