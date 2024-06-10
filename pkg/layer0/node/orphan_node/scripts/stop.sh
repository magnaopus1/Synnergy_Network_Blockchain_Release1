#!/bin/bash

# Orphan Node Stop Script
# This script stops the Orphan Node safely, ensuring all processes are terminated gracefully.

# Configuration
CONFIG_PATH="/etc/orphan_node/config.toml"
LOG_FILE="/var/log/orphan_node/orphan_node.log"

# Load configuration
if [ -f $CONFIG_PATH ]; then
    source $CONFIG_PATH
else
    echo "Configuration file not found at $CONFIG_PATH"
    exit 1
fi

# Function to stop the Orphan Node process
stop_orphan_node() {
    echo "Stopping Orphan Node..."

    # Get the process ID of the Orphan Node
    PID=$(pgrep -f orphan_node)

    if [ -z "$PID" ]; then
        echo "Orphan Node is not running."
    else
        echo "Found Orphan Node process with PID: $PID"

        # Attempt to gracefully stop the process
        kill -SIGTERM $PID
        echo "Sent SIGTERM signal to Orphan Node process."

        # Wait for the process to terminate
        wait $PID

        if [ $? -eq 0 ]; then
            echo "Orphan Node stopped successfully."
        else
            echo "Failed to stop Orphan Node gracefully, forcing termination."

            # Forcefully terminate the process
            kill -SIGKILL $PID

            if [ $? -eq 0 ]; then
                echo "Orphan Node forcefully terminated."
            else
                echo "Failed to forcefully terminate Orphan Node."
            fi
        fi
    fi
}

# Function to clean up resources
cleanup_resources() {
    echo "Cleaning up resources..."

    # Remove temporary files
    rm -f /tmp/orphan_node_*
    echo "Removed temporary files."

    # Free up memory (example, adjust as needed)
    sync; echo 1 > /proc/sys/vm/drop_caches
    echo "Freed up memory."

    echo "Resource cleanup complete."
}

# Function to log the stopping process
log_stop_process() {
    echo "Logging stop process to $LOG_FILE"
    {
        echo "======================="
        echo "Orphan Node Stop Script"
        echo "======================="
        echo "Timestamp: $(date)"
        echo "Stopping Orphan Node..."
    } >> $LOG_FILE

    if [ $? -eq 0 ]; then
        echo "Stop process logged successfully."
    else
        echo "Failed to log stop process."
    fi
}

# Main
log_stop_process
stop_orphan_node
cleanup_resources

echo "Orphan Node has been stopped."
