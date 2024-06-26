#!/bin/bash

# start.sh - Script to start the Zero-Knowledge Proof Node

# Load configuration (if any)
CONFIG_FILE="/etc/zkp_node/config.toml"

if [ -f "$CONFIG_FILE" ]; then
    source "$CONFIG_FILE"
else
    echo "Configuration file not found. Using default settings."
fi

# Function to check if the service is already running
is_service_running() {
    if pgrep -f zkp_node > /dev/null; then
        return 0
    else
        return 1
    fi
}

# Function to start the Zero-Knowledge Proof Node service
start_service() {
    echo "Starting Zero-Knowledge Proof Node service..."
    
    # Start the service using systemd (if applicable)
    if systemctl is-enabled --quiet zkp_node; then
        systemctl start zkp_node
        echo "Service zkp_node started successfully."
    else
        # Start the process manually if not managed by systemd
        nohup /usr/local/bin/zkp_node > /var/log/zkp_node/zkp_node.log 2>&1 &
        echo "zkp_node process started successfully."
    fi
}

# Function to initialize necessary resources
initialize_resources() {
    echo "Initializing resources..."
    
    # Create necessary directories
    mkdir -p /var/lib/zkp_node
    mkdir -p /var/log/zkp_node
    
    # Set appropriate permissions
    chown -R $USER:$USER /var/lib/zkp_node
    chown -R $USER:$USER /var/log/zkp_node
    
    echo "Resources initialized."
}

# Function to log startup process
log_startup() {
    LOG_FILE="/var/log/zkp_node/start.log"
    echo "Logging startup process to $LOG_FILE..."
    
    {
        echo "=== Zero-Knowledge Proof Node Startup ==="
        echo "Timestamp: $(date)"
        echo "Node ID: ${node_id:-default_node_id}"
        echo "Network ID: ${network_id:-default_network_id}"
        echo "Startup initiated by: $USER"
    } >> "$LOG_FILE"
    
    echo "Startup process logged."
}

# Main script execution
echo "Initiating Zero-Knowledge Proof Node startup..."

if is_service_running; then
    echo "Zero-Knowledge Proof Node is already running."
    exit 0
fi

initialize_resources
start_service
log_startup

echo "Zero-Knowledge Proof Node has been started successfully."
