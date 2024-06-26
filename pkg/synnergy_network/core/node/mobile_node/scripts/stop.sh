#!/bin/bash

# stop.sh - Script to stop the Mobile Node

# Load configuration (if any)
CONFIG_FILE="/etc/zkp_node/config.toml"

if [ -f "$CONFIG_FILE" ]; then
    source "$CONFIG_FILE"
else
    echo "Configuration file not found. Using default settings."
fi

# Function to check if the service is running
is_service_running() {
    if pgrep -f mobile_node > /dev/null; then
        return 0
    else
        return 1
    fi
}

# Function to stop the Mobile Node service
stop_service() {
    echo "Stopping Mobile Node service..."
    
    # Stop the service using systemd (if applicable)
    if systemctl is-active --quiet mobile_node; then
        systemctl stop mobile_node
        echo "Service mobile_node stopped successfully."
    else
        # Kill the process by name (if not using systemd)
        pkill -f mobile_node
        
        # Wait for all processes to terminate
        sleep 2
        
        # Verify if the process is stopped
        if pgrep -f mobile_node > /dev/null; then
            echo "Failed to stop mobile_node process."
        else
            echo "mobile_node process stopped successfully."
        fi
    fi
}

# Function to clean up resources
cleanup_resources() {
    echo "Cleaning up resources..."
    
    # Remove temporary files
    TEMP_DIR="/var/tmp/mobile_node"
    if [ -d "$TEMP_DIR" ]; then
        rm -rf "$TEMP_DIR"
        echo "Temporary files removed from $TEMP_DIR."
    else
        echo "No temporary files found."
    fi
    
    # Remove log files older than 7 days
    find /var/log/mobile_node/ -type f -name "*.log" -mtime +7 -exec rm -f {} \;
    echo "Old log files removed."
}

# Function to log shutdown process
log_shutdown() {
    LOG_FILE="/var/log/mobile_node/stop.log"
    echo "Logging shutdown process to $LOG_FILE..."
    
    {
        echo "=== Mobile Node Shutdown ==="
        echo "Timestamp: $(date)"
        echo "Node ID: ${NODE_ID:-default_node_id}"
        echo "Network ID: ${NETWORK_ID:-default_network_id}"
        echo "Shutdown initiated by: $USER"
    } >> "$LOG_FILE"
    
    echo "Shutdown process logged."
}

# Main script execution
echo "Initiating Mobile Node shutdown..."

if is_service_running; then
    stop_service
else
    echo "Mobile Node is not running."
fi

cleanup_resources
log_shutdown

echo "Mobile Node has been stopped successfully."
