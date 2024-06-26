#!/bin/bash

# start.sh - Script to start the Mobile Node

# Load configuration (if any)
CONFIG_FILE="/etc/zkp_node/config.toml"

if [ -f "$CONFIG_FILE" ]; then
    source "$CONFIG_FILE"
else
    echo "Configuration file not found. Using default settings."
fi

# Function to check if the service is already running
is_service_running() {
    if pgrep -f mobile_node > /dev/null; then
        return 0
    else
        return 1
    fi
}

# Function to start the Mobile Node service
start_service() {
    echo "Starting Mobile Node service..."
    
    # Start the service using systemd (if applicable)
    if command -v systemctl > /dev/null && systemctl is-enabled --quiet mobile_node; then
        systemctl start mobile_node
        echo "Service mobile_node started successfully."
    else
        # Start the process manually (if not using systemd)
        nohup /usr/local/bin/mobile_node > /var/log/mobile_node/mobile_node.log 2>&1 &
        sleep 2
        
        # Verify if the process is started
        if pgrep -f mobile_node > /dev/null; then
            echo "mobile_node process started successfully."
        else
            echo "Failed to start mobile_node process."
        fi
    fi
}

# Function to initialize necessary directories and files
initialize_directories() {
    echo "Initializing directories and files..."
    
    # Create necessary directories
    mkdir -p /var/log/mobile_node
    mkdir -p /var/lib/mobile_node/proofs
    mkdir -p /var/tmp/mobile_node
    
    # Set permissions
    chown -R $USER:$USER /var/log/mobile_node
    chown -R $USER:$USER /var/lib/mobile_node
    chown -R $USER:$USER /var/tmp/mobile_node
    
    echo "Directories and files initialized."
}

# Function to log startup process
log_startup() {
    LOG_FILE="/var/log/mobile_node/start.log"
    echo "Logging startup process to $LOG_FILE..."
    
    {
        echo "=== Mobile Node Startup ==="
        echo "Timestamp: $(date)"
        echo "Node ID: ${NODE_ID:-default_node_id}"
        echo "Network ID: ${NETWORK_ID:-default_network_id}"
        echo "Startup initiated by: $USER"
    } >> "$LOG_FILE"
    
    echo "Startup process logged."
}

# Function to apply battery optimization settings
apply_battery_optimization() {
    if [ "$OPTIMIZE_BATTERY_USAGE" = true ]; then
        echo "Applying battery optimization settings..."
        
        # Placeholder for battery optimization logic
        # Example: renice or ionice commands to adjust process priority
        renice 10 -p $$ > /dev/null
        ionice -c 3 -p $$ > /dev/null
        
        echo "Battery optimization settings applied."
    fi
}

# Main script execution
echo "Initiating Mobile Node startup..."

if is_service_running; then
    echo "Mobile Node is already running."
else
    initialize_directories
    apply_battery_optimization
    start_service
    log_startup
    echo "Mobile Node has been started successfully."
fi
