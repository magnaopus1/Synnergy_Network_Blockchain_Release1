#!/bin/bash

# Orphan Node Health Check Script
# This script performs a health check on the Orphan Node, ensuring all necessary services are operational.

# Configuration
CONFIG_PATH="/etc/orphan_node/config.toml"
LOG_FILE="/var/log/orphan_node/health_check.log"
NODE_BINARY="/usr/local/bin/orphan_node"
STATUS_URL="http://localhost:8080/status"

# Load configuration
if [ -f $CONFIG_PATH ]; then
    source $CONFIG_PATH
else
    echo "Configuration file not found at $CONFIG_PATH" | tee -a $LOG_FILE
    exit 1
fi

# Function to check if the Orphan Node process is running
check_process() {
    if pgrep -f $NODE_BINARY > /dev/null 2>&1; then
        echo "Orphan Node process is running." | tee -a $LOG_FILE
        return 0
    else
        echo "Orphan Node process is not running." | tee -a $LOG_FILE
        return 1
    fi
}

# Function to check the network status
check_network() {
    echo "Checking network connectivity..." | tee -a $LOG_FILE
    if ping -c 1 google.com &> /dev/null; then
        echo "Network connectivity is active." | tee -a $LOG_FILE
        return 0
    else
        echo "Network connectivity is down." | tee -a $LOG_FILE
        return 1
    fi
}

# Function to check the node status endpoint
check_status_endpoint() {
    echo "Checking node status endpoint..." | tee -a $LOG_FILE
    HTTP_RESPONSE=$(curl --silent --write-out "HTTPSTATUS:%{http_code}" -X GET $STATUS_URL)
    HTTP_BODY=$(echo $HTTP_RESPONSE | sed -e 's/HTTPSTATUS\:.*//g')
    HTTP_STATUS=$(echo $HTTP_RESPONSE | tr -d '\n' | sed -e 's/.*HTTPSTATUS://')

    if [ "$HTTP_STATUS" -eq 200 ]; then
        echo "Node status endpoint is healthy." | tee -a $LOG_FILE
        return 0
    else
        echo "Node status endpoint is unhealthy. HTTP status: $HTTP_STATUS" | tee -a $LOG_FILE
        return 1
    fi
}

# Function to check disk space
check_disk_space() {
    echo "Checking disk space..." | tee -a $LOG_FILE
    DISK_USAGE=$(df -h / | grep -vE '^Filesystem|tmpfs|cdrom' | awk '{ print $5 }' | sed 's/%//g')

    if [ $DISK_USAGE -lt 80 ]; then
        echo "Sufficient disk space available." | tee -a $LOG_FILE
        return 0
    else
        echo "Disk space is critically low." | tee -a $LOG_FILE
        return 1
    fi
}

# Function to log the health check process
log_health_check() {
    echo "Logging health check process to $LOG_FILE"
    {
        echo "======================="
        echo "Orphan Node Health Check"
        echo "======================="
        echo "Timestamp: $(date)"
    } >> $LOG_FILE

    if [ $? -eq 0 ]; then
        echo "Health check process logged successfully." | tee -a $LOG_FILE
    else
        echo "Failed to log health check process." | tee -a $LOG_FILE
    fi
}

# Main
log_health_check
check_process
PROCESS_STATUS=$?
check_network
NETWORK_STATUS=$?
check_status_endpoint
ENDPOINT_STATUS=$?
check_disk_space
DISK_STATUS=$?

if [ $PROCESS_STATUS -eq 0 ] && [ $NETWORK_STATUS -eq 0 ] && [ $ENDPOINT_STATUS -eq 0 ] && [ $DISK_STATUS -eq 0 ]; then
    echo "Orphan Node is healthy." | tee -a $LOG_FILE
    exit 0
else
    echo "Orphan Node has health issues." | tee -a $LOG_FILE
    exit 1
fi
