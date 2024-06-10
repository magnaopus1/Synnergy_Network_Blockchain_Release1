#!/bin/bash

# Health Check Script for Synthron Hybrid Node

# Configuration
CONFIG_FILE="/etc/synthron/hybrid_node/config.toml"
LOG_FILE="/var/log/synthron/hybrid_node_health_check.log"
NODE_PID_FILE="/var/run/synthron/hybrid_node.pid"

# Load environment variables if necessary
export NODE_ENV="production"
export LOG_LEVEL="info"

# Function to log messages
log_message() {
    local message=$1
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $message" >> "$LOG_FILE"
}

# Function to check if a process is running
is_running() {
    local pid=$1
    if [ -d "/proc/$pid" ]; then
        return 0
    else
        return 1
    fi
}

# Function to check if the node process is running
check_node_process() {
    if [ -f "$NODE_PID_FILE" ]; then
        local pid=$(cat "$NODE_PID_FILE")
        if is_running "$pid"; then
            log_message "Hybrid Node is running with PID: $pid"
            return 0
        else
            log_message "Hybrid Node process not running (stale PID: $pid)"
            return 1
        fi
    else
        log_message "Hybrid Node PID file not found"
        return 1
    fi
}

# Function to check node status via its API endpoint
check_node_status() {
    local status_endpoint="http://localhost:8080/status"  # Replace with actual status endpoint
    local response=$(curl --silent --max-time 5 "$status_endpoint")
    if [[ "$response" == *"OK"* ]]; then
        log_message "Hybrid Node status check passed: $response"
        return 0
    else
        log_message "Hybrid Node status check failed: $response"
        return 1
    fi
}

# Function to check resource usage (CPU, memory, disk)
check_resource_usage() {
    local cpu_usage=$(top -b -n1 | grep "Cpu(s)" | awk '{print $2 + $4}')
    local mem_usage=$(free | grep Mem | awk '{print $3/$2 * 100.0}')
    local disk_usage=$(df / | grep / | awk '{print $5}' | sed 's/%//g')

    log_message "Resource Usage - CPU: ${cpu_usage}%, Memory: ${mem_usage}%, Disk: ${disk_usage}%"

    if (( $(echo "$cpu_usage > 90.0" | bc -l) )) || (( $(echo "$mem_usage > 90.0" | bc -l) )) || (( $disk_usage > 90 )); then
        log_message "Resource usage critical: CPU: ${cpu_usage}%, Memory: ${mem_usage}%, Disk: ${disk_usage}%"
        return 1
    fi
    return 0
}

# Main health check execution
log_message "Starting health check for Synthron Hybrid Node"

# Perform health checks
check_node_process
process_check=$?

check_node_status
status_check=$?

check_resource_usage
resource_check=$?

# Evaluate overall health status
if [[ $process_check -eq 0 && $status_check -eq 0 && $resource_check -eq 0 ]]; then
    log_message "Hybrid Node health check passed"
    exit 0
else
    log_message "Hybrid Node health check failed"
    exit 1
fi
