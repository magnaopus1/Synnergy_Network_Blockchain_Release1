#!/bin/bash

# Forensic Node Health Check Script
# This script performs a health check on the Forensic Node, ensuring all necessary services and components are running correctly.

# Function to check if a process is running
check_process() {
    if pgrep -x "$1" > /dev/null
    then
        echo "$1 is running."
    else
        echo "$1 is not running."
        exit 1
    fi
}

# Function to check if a service is active
check_service() {
    if systemctl is-active --quiet "$1"
    then
        echo "$1 service is active."
    else
        echo "$1 service is not active."
        exit 1
    fi
}

# Function to check disk space
check_disk_space() {
    THRESHOLD=90
    USAGE=$(df -h / | grep -vE '^Filesystem' | awk '{ print $5 }' | sed 's/%//g')

    if [ "$USAGE" -lt "$THRESHOLD" ]
    then
        echo "Disk space is sufficient: ${USAGE}% used."
    else
        echo "Disk space is critically low: ${USAGE}% used."
        exit 1
    fi
}

# Function to check CPU usage
check_cpu_usage() {
    THRESHOLD=85
    USAGE=$(top -bn1 | grep "Cpu(s)" | sed "s/.*, *\([0-9.]*\)%* id.*/\1/" | awk '{print 100 - $1}')

    if (( $(echo "$USAGE < $THRESHOLD" |bc -l) ))
    then
        echo "CPU usage is within limits: ${USAGE}% used."
    else
        echo "CPU usage is critically high: ${USAGE}% used."
        exit 1
    fi
}

# Function to check memory usage
check_memory_usage() {
    THRESHOLD=90
    USAGE=$(free | grep Mem | awk '{print $3/$2 * 100.0}')

    if (( $(echo "$USAGE < $THRESHOLD" |bc -l) ))
    then
        echo "Memory usage is within limits: ${USAGE}% used."
    else
        echo "Memory usage is critically high: ${USAGE}% used."
        exit 1
    fi
}

# Function to check network connectivity
check_network_connectivity() {
    HOST="google.com"
    if ping -c 1 "$HOST" &> /dev/null
    then
        echo "Network connectivity is available."
    else
        echo "No network connectivity."
        exit 1
    fi
}

# Function to check if forensic node binary exists and is executable
check_forensic_node_binary() {
    if [ -x "./forensic_node" ]
    then
        echo "Forensic Node binary is present and executable."
    else
        echo "Forensic Node binary is missing or not executable."
        exit 1
    fi
}

# Main health check function
perform_health_check() {
    echo "Performing health check for Forensic Node..."
    
    check_forensic_node_binary
    check_process "forensic_node"
    check_disk_space
    check_cpu_usage
    check_memory_usage
    check_network_connectivity

    echo "All health checks passed successfully."
}

# Execute the health check
perform_health_check
