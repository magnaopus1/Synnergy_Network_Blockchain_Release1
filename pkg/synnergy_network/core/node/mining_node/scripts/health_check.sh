#!/bin/bash

# Mining Node Health Check Script
# This script checks the health and performance of a mining node to ensure optimal operation.

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

# Check System Load
check_system_load() {
    echo "Checking system load..."
    load=$(uptime | awk -F'[a-z]:' '{ print $2 }' | xargs)
    echo "System load: $load"
}

# Check GPU Status
check_gpu_status() {
    if command_exists nvidia-smi; then
        echo "Checking GPU status..."
        nvidia-smi --query-gpu=name,temperature.gpu,utilization.gpu,memory.used,memory.total --format=csv,noheader,nounits
    else
        echo "nvidia-smi not found. Skipping GPU check."
    fi
}

# Check CPU Usage
check_cpu_usage() {
    echo "Checking CPU usage..."
    top -bn1 | grep "Cpu(s)" | \
        sed "s/.*, *\([0-9.]*\)%* id.*/\1/" | \
        awk '{print "CPU Load: " 100 - $1"%"}'
}

# Check Memory Usage
check_memory_usage() {
    echo "Checking memory usage..."
    free -m | awk 'NR==2{printf "Memory Usage: %s/%sMB (%.2f%%)\n", $3, $2, $3*100/$2 }'
}

# Check Disk Usage
check_disk_usage() {
    echo "Checking disk usage..."
    df -h | grep -E '^/dev/' | awk '{ print $1 ": " $5 }'
}

# Check Network Connectivity
check_network_connectivity() {
    echo "Checking network connectivity..."
    if ping -c 1 google.com &> /dev/null; then
        echo "Network is up"
    else
        echo "Network is down. Please check your connection."
    fi
}

# Check Blockchain Synchronization
check_blockchain_sync() {
    echo "Checking blockchain synchronization..."
    local_sync_height=$(curl -s http://localhost:8080/api/sync/status | jq '.sync_info.latest_block_height')
    network_sync_height=$(curl -s https://blockchain-node-api.synthron.com/api/status | jq '.sync_info.latest_block_height')

    echo "Local sync height: $local_sync_height"
    echo "Network sync height: $network_sync_height"

    if [ "$local_sync_height" -ge "$network_sync_height" ]; then
        echo "Node is synchronized with the network."
    else
        echo "Node is not synchronized. Local height is $local_sync_height, network height is $network_sync_height."
    fi
}

# Check for Security Updates
check_security_updates() {
    echo "Checking for security updates..."
    sudo apt-get update -y && sudo apt-get upgrade -y
}

# Main health check function
main() {
    echo "Starting health check for mining node..."

    check_essential_commands
    check_system_load
    check_gpu_status
    check_cpu_usage
    check_memory_usage
    check_disk_usage
    check_network_connectivity
    check_blockchain_sync
    check_security_updates

    echo "Health check completed."
}

# Run the health check
main
