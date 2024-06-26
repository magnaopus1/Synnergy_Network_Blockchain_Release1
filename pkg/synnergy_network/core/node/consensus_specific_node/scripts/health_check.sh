#!/bin/bash

# health_check.sh - Script to perform health checks on the Consensus-Specific Node

# Define the node identifier for logging
NODE_ID="Consensus-Specific Node"

# Log file location
LOG_FILE="/var/log/synthron/consensus_specific_node/health_check.log"

# PID file location
PID_FILE="/var/run/synthron/consensus_specific_node.pid"

# Function to log messages with timestamps
log_message() {
    local MESSAGE="$1"
    echo "$(date '+%Y-%m-%d %H:%M:%S') - ${NODE_ID} - ${MESSAGE}" | tee -a "$LOG_FILE"
}

# Function to check if the node is running
check_node_running() {
    if [ -f "$PID_FILE" ]; then
        NODE_PID=$(cat "$PID_FILE")
        if ps -p "$NODE_PID" > /dev/null; then
            log_message "Node is running with PID $NODE_PID."
            return 0
        else
            log_message "PID file found but no running process with PID $NODE_PID."
            return 1
        fi
    else
        log_message "No PID file found. Node is not running."
        return 1
    fi
}

# Function to check network connectivity
check_network_connectivity() {
    local HOST="8.8.8.8"
    local PORT="53"
    if nc -zw1 $HOST $PORT; then
        log_message "Network connectivity check passed."
        return 0
    else
        log_message "Network connectivity check failed."
        return 1
    fi
}

# Function to check disk space usage
check_disk_space() {
    local THRESHOLD=90
    local USAGE=$(df / | grep / | awk '{ print $5 }' | sed 's/%//g')
    if [ "$USAGE" -ge "$THRESHOLD" ]; then
        log_message "Disk space usage is critical: ${USAGE}% used."
        return 1
    else
        log_message "Disk space usage is within limits: ${USAGE}% used."
        return 0
    fi
}

# Function to check CPU usage
check_cpu_usage() {
    local THRESHOLD=90
    local USAGE=$(top -bn1 | grep "Cpu(s)" | sed "s/.*, *\([0-9.]*\)%* id.*/\1/" | awk '{ print 100 - $1 }')
    if (( $(echo "$USAGE > $THRESHOLD" |bc -l) )); then
        log_message "CPU usage is critical: ${USAGE}% used."
        return 1
    else
        log_message "CPU usage is within limits: ${USAGE}% used."
        return 0
    fi
}

# Function to check memory usage
check_memory_usage() {
    local THRESHOLD=90
    local USAGE=$(free | grep Mem | awk '{print $3/$2 * 100.0}')
    if (( $(echo "$USAGE > $THRESHOLD" |bc -l) )); then
        log_message "Memory usage is critical: ${USAGE}% used."
        return 1
    else
        log_message "Memory usage is within limits: ${USAGE}% used."
        return 0
    fi
}

# Run all health checks
log_message "Starting health checks for ${NODE_ID}..."

check_node_running
NODE_STATUS=$?

check_network_connectivity
NETWORK_STATUS=$?

check_disk_space
DISK_STATUS=$?

check_cpu_usage
CPU_STATUS=$?

check_memory_usage
MEMORY_STATUS=$?

# Evaluate overall health status
if [ $NODE_STATUS -eq 0 ] && [ $NETWORK_STATUS -eq 0 ] && [ $DISK_STATUS -eq 0 ] && [ $CPU_STATUS -eq 0 ] && [ $MEMORY_STATUS -eq 0 ]; then
    log_message "All health checks passed. Node is healthy."
    exit 0
else
    log_message "One or more health checks failed. Please investigate."
    exit 1
fi
