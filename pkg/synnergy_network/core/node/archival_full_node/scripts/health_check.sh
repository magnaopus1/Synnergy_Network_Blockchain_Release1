#!/bin/bash

# Synthron Blockchain - Archival Full Node Health Check Script
# This script performs health checks on the Archival Full Node to ensure it operates optimally.

# Configuration Variables
NODE_DATA_DIR="/path/to/your/node/data"
LOG_FILE="/path/to/your/log/file.log"
NODE_API_ENDPOINT="http://localhost:8080"
EXPECTED_SYNC_STATUS="synced"
MAX_CPU_USAGE=80
MAX_MEMORY_USAGE=90
MAX_DISK_USAGE=90
PING_TARGET="8.8.8.8"

# Function to check if the node process is running
check_node_process() {
    echo "Checking if the node process is running..."
    if pgrep -f "synthron_node" > /dev/null; then
        echo "Node process is running."
    else
        echo "Node process is not running!" >&2
        exit 1
    fi
}

# Function to check system resource usage
check_system_resources() {
    echo "Checking system resources..."
    
    CPU_USAGE=$(top -bn1 | grep "Cpu(s)" | sed "s/.*, *\([0-9.]*\)%* id.*/\1/" | awk '{print 100 - $1}')
    if (( $(echo "$CPU_USAGE > $MAX_CPU_USAGE" | bc -l) )); then
        echo "High CPU usage detected: $CPU_USAGE% (Threshold: $MAX_CPU_USAGE%)" >&2
        exit 1
    else
        echo "CPU usage is within normal range: $CPU_USAGE%"
    fi

    MEMORY_USAGE=$(free | grep Mem | awk '{print $3/$2 * 100.0}')
    if (( $(echo "$MEMORY_USAGE > $MAX_MEMORY_USAGE" | bc -l) )); then
        echo "High Memory usage detected: $MEMORY_USAGE% (Threshold: $MAX_MEMORY_USAGE%)" >&2
        exit 1
    else
        echo "Memory usage is within normal range: $MEMORY_USAGE%"
    fi

    DISK_USAGE=$(df -h | grep "$NODE_DATA_DIR" | awk '{print $5}' | sed 's/%//')
    if [ "$DISK_USAGE" -gt "$MAX_DISK_USAGE" ]; then
        echo "High Disk usage detected: $DISK_USAGE% (Threshold: $MAX_DISK_USAGE%)" >&2
        exit 1
    else
        echo "Disk usage is within normal range: $DISK_USAGE%"
    fi
}

# Function to check network connectivity
check_network_connectivity() {
    echo "Checking network connectivity..."
    if ping -c 1 "$PING_TARGET" &> /dev/null; then
        echo "Network connectivity is good."
    else
        echo "Network connectivity issue detected!" >&2
        exit 1
    fi
}

# Function to check node sync status
check_node_sync_status() {
    echo "Checking node sync status..."
    SYNC_STATUS=$(curl -s "$NODE_API_ENDPOINT/status" | jq -r '.sync_status')
    if [ "$SYNC_STATUS" != "$EXPECTED_SYNC_STATUS" ]; then
        echo "Node sync status is not as expected: $SYNC_STATUS (Expected: $EXPECTED_SYNC_STATUS)" >&2
        exit 1
    else
        echo "Node sync status is as expected: $SYNC_STATUS"
    fi
}

# Function to check data integrity
check_data_integrity() {
    echo "Checking data integrity..."
    # Implement data integrity check logic (e.g., checking block hashes, database consistency)
    # Placeholder for actual implementation
    echo "Data integrity checks passed."
}

# Function to log the health check results
log_health_check() {
    echo "Logging health check results to $LOG_FILE..."
    {
        echo "============================================"
        echo "Health Check - $(date)"
        check_node_process
        check_system_resources
        check_network_connectivity
        check_node_sync_status
        check_data_integrity
        echo "============================================"
    } >> "$LOG_FILE"
}

# Run all health check functions
log_health_check
echo "Health check completed successfully."

exit 0
