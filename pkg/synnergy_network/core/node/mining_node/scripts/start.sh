#!/bin/bash

# Mining Node Start Script
# This script starts the mining node for the Synthron blockchain, ensuring all prerequisites are met and the node is configured for optimal performance.

# Load Configuration
CONFIG_FILE="/path/to/your/mining_node/config.toml"
source $CONFIG_FILE

# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Check for essential commands and tools
check_essential_commands() {
    commands=("curl" "jq" "nvidia-smi" "lshw" "grep" "awk")
    for cmd in "${commands[@]}"; do
        if ! command_exists $cmd; then
            echo "Error: $cmd is not installed. Please install it and rerun this script."
            exit 1
        fi
    done
}

# Set up logging
LOG_DIR="/var/log/mining_node"
mkdir -p $LOG_DIR
LOG_FILE="$LOG_DIR/start.log"

# Redirect stdout and stderr to the log file
exec > >(tee -a $LOG_FILE) 2>&1

# Function to check system requirements
check_system_requirements() {
    echo "Checking system requirements..."

    # Check RAM
    RAM_AVAILABLE=$(grep MemTotal /proc/meminfo | awk '{print $2}')
    if [ "$RAM_AVAILABLE" -lt 16000000 ]; then
        echo "Error: At least 16GB of RAM is required."
        exit 1
    else
        echo "RAM check passed: $(($RAM_AVAILABLE / 1024)) MB available."
    fi

    # Check SSD Storage
    SSD_AVAILABLE=$(df -h | grep '/$' | awk '{print $4}')
    if [[ "${SSD_AVAILABLE}" == *G && "${SSD_AVAILABLE%G}" -lt 500 ]]; then
        echo "Error: At least 500GB of SSD storage is required."
        exit 1
    else
        echo "SSD Storage check passed: $SSD_AVAILABLE available."
    fi

    # Check GPU or ASIC availability
    if command_exists nvidia-smi; then
        GPU_COUNT=$(nvidia-smi --query-gpu=count --format=csv,noheader,nounits)
        if [ "$GPU_COUNT" -lt 1 ]; then
            echo "Error: No compatible GPUs found."
            exit 1
        else
            echo "GPU check passed: $GPU_COUNT GPU(s) available."
        fi
    else
        echo "nvidia-smi not found. Skipping GPU check."
    fi
}

# Function to start mining software
start_mining_software() {
    echo "Starting mining software..."

    MINING_SOFTWARE="/path/to/mining/software"
    CONFIG_FILE="/path/to/mining/config"

    if [ ! -f "$MINING_SOFTWARE" ]; then
        echo "Error: Mining software not found at $MINING_SOFTWARE."
        exit 1
    fi

    if [ ! -f "$CONFIG_FILE" ]; then
        echo "Error: Mining software config file not found at $CONFIG_FILE."
        exit 1
    fi

    # Start mining software with config
    nohup $MINING_SOFTWARE -c $CONFIG_FILE &
    MINING_PID=$!

    echo "Mining software started with PID $MINING_PID."
}

# Function to configure firewall rules
configure_firewall() {
    echo "Configuring firewall rules..."

    FIREWALL_CMD="ufw"
    if ! command_exists $FIREWALL_CMD; then
        echo "Error: $FIREWALL_CMD is not installed."
        exit 1
    fi

    sudo ufw allow 8333/tcp
    sudo ufw enable
    echo "Firewall rules configured."
}

# Function to set up VPN
setup_vpn() {
    echo "Setting up VPN..."

    VPN_CMD="openvpn"
    VPN_CONFIG="/path/to/vpn/config.ovpn"

    if ! command_exists $VPN_CMD; then
        echo "Error: $VPN_CMD is not installed."
        exit 1
    fi

    if [ ! -f "$VPN_CONFIG" ]; then
        echo "Error: VPN config file not found at $VPN_CONFIG."
        exit 1
    fi

    sudo $VPN_CMD --config $VPN_CONFIG &
    VPN_PID=$!
    echo "VPN started with PID $VPN_PID."
}

# Main start function
main() {
    echo "Starting mining node..."

    check_essential_commands
    check_system_requirements
    configure_firewall
    setup_vpn
    start_mining_software

    echo "Mining node started successfully."
}

# Run the start function
main
