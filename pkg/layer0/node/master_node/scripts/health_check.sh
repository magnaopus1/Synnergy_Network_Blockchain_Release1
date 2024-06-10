#!/bin/bash

# Synthron Master Node Health Check Script
# This script checks the health and status of the Synthron Master Node.

# Function to print messages
log_message() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $1"
}

# Function to ensure the log directory exists
ensure_log_directory() {
    LOG_DIR="/var/log/synthron"
    if [ ! -d "$LOG_DIR" ]; then
        mkdir -p "$LOG_DIR"
        log_message "Created log directory: $LOG_DIR"
    fi
}

# Function to check if the node is running
check_node_status() {
    PID_FILE="/var/run/synthron_master_node.pid"
    if [ -f "$PID_FILE" ]; then
        PID=$(cat "$PID_FILE")
        if ps -p "$PID" > /dev/null 2>&1; then
            log_message "Master Node is running with PID: $PID"
        else
            log_message "Error: Master Node PID file exists but process is not running."
            exit 1
        fi
    else
        log_message "Error: Master Node PID file not found."
        exit 1
    fi
}

# Function to check system resources
check_system_resources() {
    log_message "Checking system resources..."

    # Check CPU usage
    CPU_USAGE=$(top -b -n1 | grep "Cpu(s)" | awk '{print $2 + $4}')
    if (( $(echo "$CPU_USAGE > 80.0" | bc -l) )); then
        log_message "Warning: High CPU usage detected: $CPU_USAGE%"
    else
        log_message "CPU usage is within normal range: $CPU_USAGE%"
    fi

    # Check memory usage
    MEM_USAGE=$(free | grep Mem | awk '{print $3/$2 * 100.0}')
    if (( $(echo "$MEM_USAGE > 80.0" | bc -l) )); then
        log_message "Warning: High memory usage detected: $MEM_USAGE%"
    else
        log_message "Memory usage is within normal range: $MEM_USAGE%"
    fi

    # Check disk usage
    DISK_USAGE=$(df -h | grep '/$' | awk '{print $5}' | sed 's/%//')
    if (( DISK_USAGE > 80 )); then
        log_message "Warning: High disk usage detected: $DISK_USAGE%"
    else
        log_message "Disk usage is within normal range: $DISK_USAGE%"
    fi
}

# Function to check network connectivity
check_network() {
    log_message "Checking network connectivity..."
    if ! ping -c 1 google.com &> /dev/null; then
        log_message "Error: No network connectivity. Please check your internet connection."
        exit 1
    fi
    log_message "Network connectivity is OK."
}

# Function to check node synchronization
check_node_sync() {
    log_message "Checking node synchronization..."

    NODE_STATUS=$(curl -s http://localhost:30303/status | jq '.syncing')
    if [ "$NODE_STATUS" = "false" ]; then
        log_message "Master Node is synchronized with the blockchain."
    else
        log_message "Warning: Master Node is not synchronized with the blockchain."
    fi
}

# Function to ensure security measures are active
check_security() {
    log_message "Checking security measures..."

    # Check for firewall status
    if command -v ufw &> /dev/null; then
        UFW_STATUS=$(ufw status | grep Status | awk '{print $2}')
        if [ "$UFW_STATUS" != "active" ]; then
            log_message "Warning: Firewall (UFW) is not active."
        else
            log_message "Firewall (UFW) is active."
        fi
    fi

    # Check fail2ban status
    if command -v fail2ban-client &> /dev/null; then
        FAIL2BAN_STATUS=$(fail2ban-client status | grep Status | awk '{print $2}')
        if [ "$FAIL2BAN_STATUS" != "active" ]; then
            log_message "Warning: fail2ban is not active."
        else
            log_message "fail2ban is active."
        fi
    fi
}

# Main script execution
log_message "Starting Synthron Master Node health check..."

# Ensure log directory exists
ensure_log_directory

# Check if node is running
check_node_status

# Check system resources
check_system_resources

# Check network connectivity
check_network

# Check node synchronization
check_node_sync

# Check security measures
check_security

log_message "Synthron Master Node health check completed successfully."
