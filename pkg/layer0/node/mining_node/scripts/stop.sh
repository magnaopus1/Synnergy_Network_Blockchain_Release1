#!/bin/bash

# Mining Node Stop Script
# This script stops the mining node for the Synthron blockchain, ensuring all processes are terminated safely and logs are maintained.

# Load Configuration
CONFIG_FILE="/path/to/your/mining_node/config.toml"
source $CONFIG_FILE

# Set up logging
LOG_DIR="/var/log/mining_node"
mkdir -p $LOG_DIR
LOG_FILE="$LOG_DIR/stop.log"

# Redirect stdout and stderr to the log file
exec > >(tee -a $LOG_FILE) 2>&1

# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to stop the mining software
stop_mining_software() {
    echo "Stopping mining software..."

    MINING_PID=$(pgrep -f "path/to/mining/software")

    if [ -z "$MINING_PID" ]; then
        echo "Mining software is not running."
    else
        kill -SIGTERM $MINING_PID
        echo "Mining software with PID $MINING_PID has been stopped."
    fi
}

# Function to stop the VPN
stop_vpn() {
    echo "Stopping VPN..."

    VPN_PID=$(pgrep -f "openvpn --config /path/to/vpn/config.ovpn")

    if [ -z "$VPN_PID" ]; then
        echo "VPN is not running."
    else
        kill -SIGTERM $VPN_PID
        echo "VPN with PID $VPN_PID has been stopped."
    fi
}

# Function to disable firewall rules
disable_firewall() {
    echo "Disabling firewall rules..."

    FIREWALL_CMD="ufw"
    if command_exists $FIREWALL_CMD; then
        sudo ufw delete allow 8333/tcp
        echo "Firewall rules disabled."
    else
        echo "Error: $FIREWALL_CMD is not installed."
        exit 1
    fi
}

# Function to save the current state and logs
save_state_and_logs() {
    echo "Saving current state and logs..."

    STATE_DIR="/path/to/mining_node/state"
    mkdir -p $STATE_DIR

    # Save the current state of the blockchain and mining software
    cp -r /path/to/mining_node/data $STATE_DIR/data_backup_$(date +%Y%m%d_%H%M%S)
    cp $LOG_DIR/* $STATE_DIR/

    echo "Current state and logs have been saved."
}

# Function to clean up temporary files
cleanup_temp_files() {
    echo "Cleaning up temporary files..."

    TEMP_DIR="/path/to/mining_node/temp"
    rm -rf $TEMP_DIR/*

    echo "Temporary files have been cleaned up."
}

# Main stop function
main() {
    echo "Stopping mining node..."

    stop_mining_software
    stop_vpn
    disable_firewall
    save_state_and_logs
    cleanup_temp_files

    echo "Mining node stopped successfully."
}

# Run the stop function
main
