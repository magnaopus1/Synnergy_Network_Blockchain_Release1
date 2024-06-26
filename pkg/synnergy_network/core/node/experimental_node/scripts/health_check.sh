#!/bin/bash

# Load environment variables
source /path/to/.env

# Function to check node status
check_node_status() {
    echo "Checking Experimental Node status..."

    # Check if the node process is running
    NODE_PID=$(pgrep -f experimental_node)
    if [ -z "$NODE_PID" ]; then
        echo "Experimental Node is not running."
        return 1
    else
        echo "Experimental Node is running with PID: $NODE_PID"
        return 0
    fi
}

# Function to check blockchain synchronization
check_blockchain_sync() {
    echo "Checking blockchain synchronization status..."

    SYNC_STATUS=$(curl -s http://localhost:$SYNC_PORT/sync_status)
    if [ "$SYNC_STATUS" == "synced" ]; then
        echo "Blockchain is fully synchronized."
        return 0
    else
        echo "Blockchain is not synchronized. Current status: $SYNC_STATUS"
        return 1
    fi
}

# Function to check disk usage
check_disk_usage() {
    echo "Checking disk usage..."

    USAGE=$(df /path/to/data/directory | tail -1 | awk '{print $5}')
    if [ ${USAGE%?} -gt 90 ]; then
        echo "Disk usage is above 90%. Current usage: $USAGE"
        return 1
    else
        echo "Disk usage is within safe limits. Current usage: $USAGE"
        return 0
    fi
}

# Function to check network connectivity
check_network_connectivity() {
    echo "Checking network connectivity..."

    if ping -c 1 google.com &> /dev/null; then
        echo "Network connectivity is active."
        return 0
    else
        echo "Network connectivity is down."
        return 1
    fi
}

# Function to check for critical errors in logs
check_logs_for_errors() {
    echo "Checking logs for critical errors..."

    if grep -i "critical" /path/to/logs/experimental_node.log &> /dev/null; then
        echo "Critical errors found in logs."
        return 1
    else
        echo "No critical errors found in logs."
        return 0
    fi
}

# Main health check function
perform_health_check() {
    echo "Performing comprehensive health check..."

    check_node_status
    NODE_STATUS=$?

    check_blockchain_sync
    SYNC_STATUS=$?

    check_disk_usage
    DISK_STATUS=$?

    check_network_connectivity
    NETWORK_STATUS=$?

    check_logs_for_errors
    LOGS_STATUS=$?

    if [ $NODE_STATUS -eq 0 ] && [ $SYNC_STATUS -eq 0 ] && [ $DISK_STATUS -eq 0 ] && [ $NETWORK_STATUS -eq 0 ] && [ $LOGS_STATUS -eq 0 ]; then
        echo "All health checks passed."
        exit 0
    else
        echo "One or more health checks failed."
        exit 1
    fi
}

# Execute the health check
perform_health_check
