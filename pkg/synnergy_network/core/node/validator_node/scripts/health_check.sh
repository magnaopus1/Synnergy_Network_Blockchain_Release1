#!/bin/bash

# Synthron Blockchain Validator Node Health Check Script

# Function to check CPU usage
check_cpu_usage() {
    echo "Checking CPU usage..."
    cpu_usage=$(top -bn1 | grep "Cpu(s)" | sed "s/.*, *\([0-9.]*\)%* id.*/\1/" | awk '{print 100 - $1}')
    echo "Current CPU usage: $cpu_usage%"
    if (( $(echo "$cpu_usage > 85" | bc -l) )); then
        echo "Warning: CPU usage is above 85%."
    fi
}

# Function to check memory usage
check_memory_usage() {
    echo "Checking memory usage..."
    mem_usage=$(free -m | awk 'NR==2{printf "%.2f", $3*100/$2 }')
    echo "Current memory usage: $mem_usage%"
    if (( $(echo "$mem_usage > 85" | bc -l) )); then
        echo "Warning: Memory usage is above 85%."
    fi
}

# Function to check disk usage
check_disk_usage() {
    echo "Checking disk usage..."
    disk_usage=$(df -h / | awk 'NR==2 {print $5}' | sed 's/%//g')
    echo "Current disk usage: $disk_usage%"
    if [ "$disk_usage" -gt 85 ]; then
        echo "Warning: Disk usage is above 85%."
    fi
}

# Function to check network connectivity
check_network_connectivity() {
    echo "Checking network connectivity..."
    ping -c 4 8.8.8.8 > /dev/null 2>&1
    if [ $? -ne 0 ]; then
        echo "Error: Network connectivity is down."
    else
        echo "Network connectivity is up."
    fi
}

# Function to check node synchronization status
check_node_sync_status() {
    echo "Checking node synchronization status..."
    sync_status=$(curl -s http://localhost:26657/status | jq -r .result.sync_info.catching_up)
    if [ "$sync_status" == "false" ]; then
        echo "Node is synchronized with the network."
    else
        echo "Node is catching up with the network. Please wait..."
    fi
}

# Function to check validator status
check_validator_status() {
    echo "Checking validator status..."
    validator_address=$(jq -r .address < ~/.synthron/config/priv_validator_key.json)
    validator_info=$(curl -s http://localhost:26657/validators | jq --arg addr "$validator_address" '.result.validators[] | select(.address == $addr)')
    if [ -z "$validator_info" ]; then
        echo "Error: Validator is not in the active set."
    else
        echo "Validator is active in the network."
    fi
}

# Function to check for latest software updates
check_for_updates() {
    echo "Checking for software updates..."
    # Assuming the use of a package manager like apt-get for updates
    sudo apt-get update > /dev/null 2>&1
    updates=$(sudo apt-get -s upgrade | grep -P '^\d+ upgraded')
    if [ -n "$updates" ]; then
        echo "Warning: There are pending software updates."
    else
        echo "All software packages are up to date."
    fi
}

# Function to perform a full health check
perform_health_check() {
    echo "Performing full health check for Synthron Validator Node..."

    check_cpu_usage
    check_memory_usage
    check_disk_usage
    check_network_connectivity
    check_node_sync_status
    check_validator_status
    check_for_updates

    echo "Health check completed."
}

# Run the health check
perform_health_check
