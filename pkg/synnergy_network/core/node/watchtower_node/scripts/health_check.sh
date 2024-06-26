#!/bin/bash

# Health Check Script for Watchtower Node
# This script checks the health status of the Watchtower Node

NODE_NAME="synthron_watchtower"
PID_FILE="/var/run/${NODE_NAME}.pid"
LOG_FILE="/var/log/${NODE_NAME}/health_check.log"
ERROR_LOG_FILE="/var/log/${NODE_NAME}/health_check_error.log"
CHECK_INTERVAL=60  # Time in seconds between health checks
HEALTH_ENDPOINT="http://localhost:8080/health"  # Adjust this endpoint as necessary

# Function to log messages
log_message() {
    local message=$1
    echo "$(date +'%Y-%m-%d %H:%M:%S') - ${message}" | tee -a $LOG_FILE
}

# Function to log errors
log_error() {
    local message=$1
    echo "$(date +'%Y-%m-%d %H:%M:%S') - ERROR: ${message}" | tee -a $ERROR_LOG_FILE
}

# Function to check if the Watchtower Node process is running
check_process() {
    if [ ! -f "$PID_FILE" ]; then
        log_error "PID file not found. Watchtower Node might not be running."
        return 1
    fi

    PID=$(cat "$PID_FILE")
    if ps -p $PID > /dev/null; then
        log_message "Watchtower Node is running with PID: $PID"
        return 0
    else
        log_error "No process found with PID: $PID. Watchtower Node might not be running."
        return 1
    fi
}

# Function to check the health endpoint
check_health_endpoint() {
    response=$(curl --silent --write-out "HTTPSTATUS:%{http_code}" -X GET $HEALTH_ENDPOINT)
    http_status=$(echo $response | tr -d '\n' | sed -e 's/.*HTTPSTATUS://')

    if [ "$http_status" -ne 200 ]; then
        log_error "Health check failed with status code: $http_status"
        return 1
    else
        log_message "Health check passed with status code: $http_status"
        return 0
    fi
}

# Function to perform health check
perform_health_check() {
    log_message "Performing health check for Watchtower Node..."
    check_process
    process_status=$?

    if [ $process_status -eq 0 ]; then
        check_health_endpoint
        health_status=$?
        if [ $health_status -eq 0 ]; then
            log_message "Watchtower Node health check passed."
        else
            log_error "Watchtower Node health endpoint check failed."
        fi
    else
        log_error "Watchtower Node process check failed."
    fi
}

# Ensure log directories exist
mkdir -p "$(dirname "$LOG_FILE")"
mkdir -p "$(dirname "$ERROR_LOG_FILE")"

# Main execution loop for continuous monitoring
while true; do
    perform_health_check
    sleep $CHECK_INTERVAL
done

exit 0
