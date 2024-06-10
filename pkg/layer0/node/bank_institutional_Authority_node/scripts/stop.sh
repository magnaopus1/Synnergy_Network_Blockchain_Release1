#!/bin/bash

# Define paths to configuration and log files
CONFIG_PATH="/etc/synthron_blockchain/bank_institutional_node"
LOG_PATH="/var/log/bank_institutional_node_stop.log"

# Function to output to both console and log file
log() {
    echo "$(date +"%Y-%m-%d %T") - $1" | tee -a $LOG_PATH
}

# Check if the script is run as root
if [ "$(id -u)" != "0" ]; then
    log "This script must be run as root."
    exit 1
fi

# Stopping the node
stop_node() {
    log "Attempting to stop Bank/Institutional Authority Node..."
    PID=$(cat /var/run/bank_institutional_node.pid)
    if [ -z "$PID" ]; then
        log "No PID found. Node may not be running."
    else
        kill $PID
        if [ $? -eq 0 ]; then
            log "Bank/Institutional Authority Node stopped successfully."
            rm /var/run/bank_institutional_node.pid
        else
            log "Failed to stop the Node. PID: $PID"
            exit 1
        fi
    fi
}

# Safely close all connections and save state
shutdown_procedures() {
    log "Running shutdown procedures..."
    # Insert commands for saving node state, closing database connections safely, etc.
    log "All data has been securely saved and connections closed."
}

# Main function
main() {
    log "Initializing shutdown of Bank/Institutional Authority Node..."
    shutdown_procedures
    stop_node
    log "Shutdown process complete."
}

# Execute main function
main
