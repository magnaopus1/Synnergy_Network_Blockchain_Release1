#!/bin/bash

# health_check.sh
# This script performs a health check on the Light Node to ensure it is running correctly
# and is able to communicate with the blockchain network.

# Function to check if the node process is running
check_node_process() {
    echo "Checking if the Light Node process is running..."
    if pgrep -f "light_node" > /dev/null; then
        echo "Light Node process is running."
    else
        echo "Light Node process is not running. Starting Light Node..."
        start_node
    fi
}

# Function to start the node
start_node() {
    # Assuming the light_node binary is in the same directory
    ./light_node &
    if [ $? -eq 0 ]; then
        echo "Light Node started successfully."
    else
        echo "Failed to start Light Node."
        exit 1
    fi
}

# Function to check network connectivity
check_network_connectivity() {
    echo "Checking network connectivity..."
    if ping -c 3 8.8.8.8 > /dev/null; then
        echo "Network connectivity is fine."
    else
        echo "Network connectivity is down."
        exit 1
    fi
}

# Function to verify synchronization status
check_sync_status() {
    echo "Checking synchronization status..."
    SYNC_STATUS=$(curl -s http://localhost:8080/sync_status)
    if [ "$SYNC_STATUS" == "synced" ]; then
        echo "Light Node is synchronized with the blockchain."
    else
        echo "Light Node is not synchronized. Current status: $SYNC_STATUS"
        exit 1
    fi
}

# Function to validate data integrity
check_data_integrity() {
    echo "Validating data integrity..."
    # Assuming there's a function in the light node to validate data
    INTEGRITY_STATUS=$(curl -s http://localhost:8080/data_integrity)
    if [ "$INTEGRITY_STATUS" == "valid" ]; then
        echo "Data integrity check passed."
    else
        echo "Data integrity check failed. Current status: $INTEGRITY_STATUS"
        exit 1
    fi
}

# Function to check disk space
check_disk_space() {
    echo "Checking disk space..."
    DISK_USAGE=$(df -h / | grep / | awk '{print $5}' | sed 's/%//g')
    if [ "$DISK_USAGE" -lt 80 ]; then
        echo "Sufficient disk space available."
    else
        echo "Low disk space. Current usage: $DISK_USAGE%"
        exit 1
    fi
}

# Function to check memory usage
check_memory_usage() {
    echo "Checking memory usage..."
    MEMORY_USAGE=$(free | grep Mem | awk '{print $3/$2 * 100.0}')
    if (( $(echo "$MEMORY_USAGE < 80.0" | bc -l) )); then
        echo "Sufficient memory available."
    else
        echo "High memory usage. Current usage: $MEMORY_USAGE%"
        exit 1
    fi
}

# Main health check procedure
main_health_check() {
    check_node_process
    check_network_connectivity
    check_sync_status
    check_data_integrity
    check_disk_space
    check_memory_usage

    echo "Light Node health check completed successfully."
}

# Execute the main health check
main_health_check
