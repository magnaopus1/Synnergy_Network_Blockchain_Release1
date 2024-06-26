#!/bin/bash

# health_check.sh - Script to perform health checks on the Zero-Knowledge Proof Node

# Load configuration (if any)
CONFIG_FILE="/etc/zkp_node/config.toml"

if [ -f "$CONFIG_FILE" ]; then
    source "$CONFIG_FILE"
else
    echo "Configuration file not found. Using default settings."
fi

# Function to check if the service is running
check_service_status() {
    if systemctl is-active --quiet zkp_node; then
        echo "Service zkp_node is running."
        return 0
    else
        echo "Service zkp_node is not running."
        return 1
    fi
}

# Function to check if the process is running
check_process_status() {
    if pgrep -f zkp_node > /dev/null; then
        echo "zkp_node process is running."
        return 0
    else
        echo "zkp_node process is not running."
        return 1
    fi
}

# Function to check if the network is reachable
check_network_reachability() {
    if ping -c 1 -W 1 8.8.8.8 > /dev/null; then
        echo "Network is reachable."
        return 0
    else
        echo "Network is not reachable."
        return 1
    fi
}

# Function to check disk space usage
check_disk_space() {
    USAGE=$(df /var/lib/zkp_node | tail -1 | awk '{print $5}' | sed 's/%//')
    if [ "$USAGE" -lt 80 ]; then
        echo "Disk space usage is under control: ${USAGE}% used."
        return 0
    else
        echo "Disk space usage is high: ${USAGE}% used."
        return 1
    fi
}

# Function to check CPU and memory usage
check_cpu_memory_usage() {
    CPU_USAGE=$(top -bn1 | grep "Cpu(s)" | sed "s/.*, *\([0-9.]*\)%* id.*/\1/" | awk '{print 100 - $1"%"}')
    MEMORY_USAGE=$(free | grep Mem | awk '{print $3/$2 * 100.0}')
    
    echo "CPU Usage: $CPU_USAGE"
    echo "Memory Usage: $MEMORY_USAGE%"
    
    if (( $(echo "$MEMORY_USAGE < 80.0" | bc -l) )); then
        echo "Memory usage is under control."
        return 0
    else
        echo "Memory usage is high."
        return 1
    fi
}

# Function to check log files for errors
check_log_files() {
    if grep -i "error" /var/log/zkp_node/zkp_node.log > /dev/null; then
        echo "Errors found in log files."
        return 1
    else
        echo "No errors found in log files."
        return 0
    fi
}

# Function to log health check results
log_health_check() {
    LOG_FILE="/var/log/zkp_node/health_check.log"
    echo "Logging health check results to $LOG_FILE..."
    
    {
        echo "=== Zero-Knowledge Proof Node Health Check ==="
        echo "Timestamp: $(date)"
        echo "Node ID: ${node_id:-default_node_id}"
        echo "Network ID: ${network_id:-default_network_id}"
        check_service_status
        check_process_status
        check_network_reachability
        check_disk_space
        check_cpu_memory_usage
        check_log_files
    } >> "$LOG_FILE"
    
    echo "Health check results logged."
}

# Main script execution
echo "Performing health checks on Zero-Knowledge Proof Node..."

check_service_status
check_process_status
check_network_reachability
check_disk_space
check_cpu_memory_usage
check_log_files
log_health_check

echo "Health checks completed."
