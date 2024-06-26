#!/bin/bash

# health_check.sh - Script to perform health check on the Mobile Node

# Load configuration (if any)
CONFIG_FILE="/etc/zkp_node/config.toml"

if [ -f "$CONFIG_FILE" ]; then
    source "$CONFIG_FILE"
else
    echo "Configuration file not found. Using default settings."
fi

# Function to check if the service is running
is_service_running() {
    if pgrep -f mobile_node > /dev/null; then
        return 0
    else
        return 1
    fi
}

# Function to check disk space usage
check_disk_space() {
    local THRESHOLD=90 # threshold percentage for disk usage
    local USAGE=$(df / | tail -1 | awk '{print $5}' | sed 's/%//')

    if [ "$USAGE" -ge "$THRESHOLD" ]; then
        echo "Warning: Disk usage is above $THRESHOLD% (currently $USAGE%)"
        return 1
    else
        echo "Disk usage is at $USAGE%, which is within acceptable limits."
        return 0
    fi
}

# Function to check CPU usage
check_cpu_usage() {
    local THRESHOLD=80 # threshold percentage for CPU usage
    local USAGE=$(top -bn1 | grep "Cpu(s)" | sed "s/.*, *\([0-9.]*\)%* id.*/\1/" | awk '{print 100 - $1}')

    if (( $(echo "$USAGE > $THRESHOLD" | bc -l) )); then
        echo "Warning: CPU usage is above $THRESHOLD% (currently $USAGE%)"
        return 1
    else
        echo "CPU usage is at $USAGE%, which is within acceptable limits."
        return 0
    fi
}

# Function to check memory usage
check_memory_usage() {
    local THRESHOLD=80 # threshold percentage for memory usage
    local USAGE=$(free | grep Mem | awk '{print $3/$2 * 100.0}')

    if (( $(echo "$USAGE > $THRESHOLD" | bc -l) )); then
        echo "Warning: Memory usage is above $THRESHOLD% (currently $USAGE%)"
        return 1
    else
        echo "Memory usage is at $USAGE%, which is within acceptable limits."
        return 0
    fi
}

# Function to check network connectivity
check_network_connectivity() {
    local HOST="8.8.8.8" # Google DNS
    if ping -c 2 "$HOST" > /dev/null; then
        echo "Network connectivity is good."
        return 0
    else
        echo "Warning: Network connectivity issues detected."
        return 1
    fi
}

# Function to check blockchain sync status
check_blockchain_sync() {
    local LAST_SYNC_TIME=$(stat -c %Y /var/lib/mobile_node/last_sync)
    local CURRENT_TIME=$(date +%s)
    local DIFF=$((CURRENT_TIME - LAST_SYNC_TIME))
    local THRESHOLD=300 # 5 minutes

    if [ "$DIFF" -gt "$THRESHOLD" ]; then
        echo "Warning: Blockchain has not been synced in the last $THRESHOLD seconds."
        return 1
    else
        echo "Blockchain sync status is up-to-date."
        return 0
    fi
}

# Function to log health check
log_health_check() {
    LOG_FILE="/var/log/mobile_node/health_check.log"
    echo "Logging health check to $LOG_FILE..."
    
    {
        echo "=== Mobile Node Health Check ==="
        echo "Timestamp: $(date)"
        echo "Node ID: ${NODE_ID:-default_node_id}"
        echo "Network ID: ${NETWORK_ID:-default_network_id}"
        echo "Service running: $(is_service_running && echo 'Yes' || echo 'No')"
        echo "Disk space usage: $(check_disk_space && echo 'Normal' || echo 'High')"
        echo "CPU usage: $(check_cpu_usage && echo 'Normal' || echo 'High')"
        echo "Memory usage: $(check_memory_usage && echo 'Normal' || echo 'High')"
        echo "Network connectivity: $(check_network_connectivity && echo 'Good' || echo 'Issues')"
        echo "Blockchain sync status: $(check_blockchain_sync && echo 'Up-to-date' || echo 'Out-of-date')"
    } >> "$LOG_FILE"
    
    echo "Health check logged."
}

# Main script execution
echo "Initiating Mobile Node health check..."

if is_service_running; then
    check_disk_space
    check_cpu_usage
    check_memory_usage
    check_network_connectivity
    check_blockchain_sync
    log_health_check
    echo "Mobile Node health check completed successfully."
else
    echo "Mobile Node is not running. Health check aborted."
    exit 1
fi
