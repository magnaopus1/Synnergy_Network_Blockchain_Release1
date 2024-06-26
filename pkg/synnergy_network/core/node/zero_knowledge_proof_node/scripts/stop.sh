#!/bin/bash

# stop.sh - Script to stop the Zero-Knowledge Proof Node

# Load configuration (if any)
CONFIG_FILE="/etc/zkp_node/config.toml"

if [ -f "$CONFIG_FILE" ]; then
    source "$CONFIG_FILE"
else
    echo "Configuration file not found. Using default settings."
fi

# Function to stop the Zero-Knowledge Proof Node service
stop_service() {
    echo "Stopping Zero-Knowledge Proof Node service..."
    
    # Stop the service using systemd (if applicable)
    if systemctl is-active --quiet zkp_node; then
        systemctl stop zkp_node
        echo "Service zkp_node stopped successfully."
    else
        echo "Service zkp_node is not running."
    fi
    
    # Kill the process by name (if not using systemd)
    pkill -f zkp_node
    
    # Wait for all processes to terminate
    sleep 2
    
    # Verify if the process is stopped
    if pgrep -f zkp_node > /dev/null; then
        echo "Failed to stop zkp_node process."
    else
        echo "zkp_node process stopped successfully."
    fi
}

# Function to clean up resources
cleanup_resources() {
    echo "Cleaning up resources..."
    
    # Remove temporary files
    TEMP_DIR="/var/tmp/zkp_node"
    if [ -d "$TEMP_DIR" ]; then
        rm -rf "$TEMP_DIR"
        echo "Temporary files removed from $TEMP_DIR."
    else
        echo "No temporary files found."
    fi
    
    # Remove log files older than 7 days
    find /var/log/zkp_node/ -type f -name "*.log" -mtime +7 -exec rm -f {} \;
    echo "Old log files removed."
}

# Function to log shutdown process
log_shutdown() {
    LOG_FILE="/var/log/zkp_node/stop.log"
    echo "Logging shutdown process to $LOG_FILE..."
    
    {
        echo "=== Zero-Knowledge Proof Node Shutdown ==="
        echo "Timestamp: $(date)"
        echo "Node ID: ${node_id:-default_node_id}"
        echo "Network ID: ${network_id:-default_network_id}"
        echo "Shutdown initiated by: $USER"
    } >> "$LOG_FILE"
    
    echo "Shutdown process logged."
}

# Main script execution
echo "Initiating Zero-Knowledge Proof Node shutdown..."
stop_service
cleanup_resources
log_shutdown
echo "Zero-Knowledge Proof Node has been stopped successfully."
