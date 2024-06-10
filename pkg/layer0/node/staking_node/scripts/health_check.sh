#!/bin/bash

# Staking Node Health Check Script
# This script performs health checks on the staking node in the Synthron blockchain network.

# Function to log information with timestamp
log_info() {
    echo "$(date +'%Y-%m-%d %H:%M:%S') [INFO] $1"
}

# Function to log warning with timestamp
log_warning() {
    echo "$(date +'%Y-%m-%d %H:%M:%S') [WARNING] $1"
}

# Function to log error with timestamp
log_error() {
    echo "$(date +'%Y-%m-%d %H:%M:%S') [ERROR] $1"
}

# Function to check if the node process is running
check_process() {
    local NODE_NAME="synthron_staking_node"
    local NODE_PID=$(pgrep -f "$NODE_NAME")

    if [ -z "$NODE_PID" ]; then
        log_error "Staking node process is not running."
        return 1
    fi

    log_info "Staking node process is running with PID: $NODE_PID"
    return 0
}

# Function to check disk space
check_disk_space() {
    local THRESHOLD=90
    local USAGE=$(df -h / | grep / | awk '{ print $5 }' | sed 's/%//g')

    if [ "$USAGE" -ge "$THRESHOLD" ]; then
        log_warning "Disk usage is above $THRESHOLD%. Current usage: $USAGE%."
        return 1
    fi

    log_info "Disk usage is below $THRESHOLD%. Current usage: $USAGE%."
    return 0
}

# Function to check memory usage
check_memory_usage() {
    local THRESHOLD=80
    local USAGE=$(free | grep Mem | awk '{print $3/$2 * 100.0}')

    if (( $(echo "$USAGE >= $THRESHOLD" | bc -l) )); then
        log_warning "Memory usage is above $THRESHOLD%. Current usage: $USAGE%."
        return 1
    fi

    log_info "Memory usage is below $THRESHOLD%. Current usage: $USAGE%."
    return 0
}

# Function to check CPU load
check_cpu_load() {
    local THRESHOLD=75
    local LOAD=$(top -bn1 | grep "load average:" | awk '{print $10}' | sed 's/,//')

    if (( $(echo "$LOAD >= $THRESHOLD" | bc -l) )); then
        log_warning "CPU load is above $THRESHOLD%. Current load: $LOAD."
        return 1
    fi

    log_info "CPU load is below $THRESHOLD%. Current load: $LOAD."
    return 0
}

# Function to check network connectivity
check_network() {
    local HOST="google.com"

    if ! ping -c 1 "$HOST" &> /dev/null; then
        log_error "Network connectivity check failed. Cannot reach $HOST."
        return 1
    fi

    log_info "Network connectivity is good."
    return 0
}

# Main function
main() {
    log_info "Starting health check for staking node..."

    check_process
    check_disk_space
    check_memory_usage
    check_cpu_load
    check_network

    log_info "Health check completed."
    exit 0
}

# Execute the main function
main
