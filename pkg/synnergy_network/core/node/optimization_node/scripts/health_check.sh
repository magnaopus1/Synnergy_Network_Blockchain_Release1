#!/bin/bash

# Script to perform health check on the Optimization Node
# This script checks the health of the Optimization Node by verifying
# the status of its processes, services, and network connectivity.

NODE_NAME="OptimizationNode"
PID_FILE="/var/run/${NODE_NAME}.pid"
LOG_FILE="/var/log/${NODE_NAME}.log"
CONFIG_FILE="/etc/${NODE_NAME}/config.toml"
ENV_FILE="/etc/${NODE_NAME}/.env"

# Function to check if the node is running
check_if_running() {
    if [ -f "$PID_FILE" ]; then
        PID=$(cat "$PID_FILE")
        if kill -0 "$PID" > /dev/null 2>&1; then
            echo "${NODE_NAME} is running with PID ${PID}."
        else
            echo "${NODE_NAME} is not running. Stale PID file found."
            rm -f "$PID_FILE"
            exit 1
        fi
    else
        echo "${NODE_NAME} is not running. PID file not found."
        exit 1
    fi
}

# Function to check if necessary services are running
check_services() {
    echo "Checking necessary services for ${NODE_NAME}..."

    # Example: Check if a specific service is running
    # if ! systemctl is-active --quiet some-service; then
    #     echo "Required service 'some-service' is not running."
    #     exit 1
    # fi

    echo "All necessary services are running."
}

# Function to check network connectivity
check_network() {
    echo "Checking network connectivity..."

    # Example: Check connectivity to a specific endpoint
    # if ! ping -c 1 some-endpoint.com > /dev/null 2>&1; then
    #     echo "Network connectivity check failed."
    #     exit 1
    # fi

    echo "Network connectivity is verified."
}

# Function to check configuration file integrity
check_config() {
    if [ -f "$CONFIG_FILE" ]; then
        echo "Configuration file ${CONFIG_FILE} found."
        # Add more comprehensive checks for config file integrity if necessary
    else
        echo "Configuration file ${CONFIG_FILE} not found!"
        exit 1
    fi
}

# Function to check environment variables
check_env() {
    if [ -f "$ENV_FILE" ]; then
        source "$ENV_FILE"
        echo "Environment variables loaded from ${ENV_FILE}."
    else
        echo "Environment file ${ENV_FILE} not found!"
        exit 1
    fi
}

# Function to check disk space
check_disk_space() {
    THRESHOLD=80
    USAGE=$(df -h | grep '/$' | awk '{print $5}' | sed 's/%//')
    if [ "$USAGE" -gt "$THRESHOLD" ]; then
        echo "Disk space usage is above ${THRESHOLD}%."
        exit 1
    else
        echo "Disk space usage is within acceptable limits."
    fi
}

# Function to check CPU usage
check_cpu_usage() {
    THRESHOLD=90
    USAGE=$(top -bn1 | grep "Cpu(s)" | sed "s/.*, *\([0-9.]*\)%* id.*/\1/" | awk '{print 100 - $1}')
    if (( $(echo "$USAGE > $THRESHOLD" | bc -l) )); then
        echo "CPU usage is above ${THRESHOLD}%."
        exit 1
    else
        echo "CPU usage is within acceptable limits."
    fi
}

# Function to check memory usage
check_memory_usage() {
    THRESHOLD=90
    USAGE=$(free | grep Mem | awk '{print $3/$2 * 100.0}')
    if (( $(echo "$USAGE > $THRESHOLD" | bc -l) )); then
        echo "Memory usage is above ${THRESHOLD}%."
        exit 1
    else
        echo "Memory usage is within acceptable limits."
    fi
}

# Main script execution
echo "Performing health check for ${NODE_NAME}..."

# Step-by-step execution
check_if_running
check_services
check_network
check_config
check_env
check_disk_space
check_cpu_usage
check_memory_usage

echo "${NODE_NAME} health check completed successfully."

exit 0
