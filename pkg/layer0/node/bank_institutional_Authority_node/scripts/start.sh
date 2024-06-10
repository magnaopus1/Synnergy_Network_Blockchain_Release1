#!/bin/bash

# Define the path to configuration files and other scripts
CONFIG_PATH="/etc/synthron_blockchain/bank_institutional_node"
LOG_PATH="/var/log/bank_institutional_node_start.log"

# Function to output to console and log file
log() {
    echo "$(date +"%Y-%m-%d %T") - $1" | tee -a $LOG_PATH
}

# Check if the script is run as root
if [ "$(id -u)" != "0" ]; then
    log "This script must be run as root."
    exit 1
fi

# Starting the node
start_node() {
    log "Starting Bank/Institutional Authority Node..."
    cd /opt/synthron_blockchain/bank_institutional_node || exit
    ./node & # Assuming the executable is named 'node' and placed in this directory
    PID=$!
    echo $PID > /var/run/bank_institutional_node.pid
    log "Bank/Institutional Authority Node started with PID $PID."
}

# Initial configuration and environment setup
setup_environment() {
    log "Setting up environment..."
    export NODE_CONFIG="$CONFIG_PATH/config.toml"
    export NODE_ENV="production"
    log "Environment setup complete."
}

# Checking prerequisites before starting the node
check_prerequisites() {
    log "Checking prerequisites..."
    # Example: Check for network connectivity
    if ! ping -c 1 -W 2 8.8.8.8 > /dev/null 2>&1; then
        log "Network connectivity check failed. Please check your network settings."
        exit 1
    fi
    # Additional checks can be added here
    log "All prerequisites met."
}

# Load additional services or dependencies
load_services() {
    log "Loading necessary services..."
    # Example: Start database service
    systemctl start mongodb
    if [ $? -ne 0 ]; then
        log "Failed to start MongoDB service."
        exit 1
    fi
    log "Services loaded successfully."
}

# Main function
main() {
    log "Initializing Bank/Institutional Authority Node startup..."
    setup_environment
    check_prerequisites
    load_services
    start_node
    log "Bank/Institutional Authority Node is operational."
}

# Execute main function
main
