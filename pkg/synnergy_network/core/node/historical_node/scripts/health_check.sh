#!/bin/bash

# health_check.sh - Script to perform health check on the Historical Node

# Define the service name and log file location
SERVICE_NAME="historical_node"
LOG_FILE="/var/log/historical_node/health_check.log"

# Function to log messages
log_message() {
    local MESSAGE=$1
    echo "$(date '+%Y-%m-%d %H:%M:%S') - ${MESSAGE}" | tee -a ${LOG_FILE}
}

# Log the start of the health check process
log_message "Initiating health check for ${SERVICE_NAME}."

# Check if the node process is running
PID=$(pgrep -f ${SERVICE_NAME})
if [ -z "$PID" ]; then
    log_message "ERROR: ${SERVICE_NAME} is not running."
    exit 1
fi
log_message "${SERVICE_NAME} is running with PID ${PID}."

# Perform a simple HTTP GET request to check the node's API health endpoint
HEALTH_ENDPOINT="http://localhost:8080/health"
HTTP_RESPONSE=$(curl --write-out "%{http_code}" --silent --output /dev/null ${HEALTH_ENDPOINT})

if [ "$HTTP_RESPONSE" -ne 200 ]; then
    log_message "ERROR: ${SERVICE_NAME} health check failed with status code ${HTTP_RESPONSE}."
    exit 1
fi
log_message "${SERVICE_NAME} health check endpoint responded with status code ${HTTP_RESPONSE}."

# Check disk space utilization
DISK_USAGE=$(df -h /var/lib/historical_node | tail -1 | awk '{print $5}')
THRESHOLD=80%
if [[ ${DISK_USAGE%?} -ge ${THRESHOLD%?} ]]; then
    log_message "ERROR: Disk usage for ${SERVICE_NAME} is at ${DISK_USAGE}, which exceeds the threshold of ${THRESHOLD}."
    exit 1
fi
log_message "Disk usage for ${SERVICE_NAME} is at ${DISK_USAGE}, which is within acceptable limits."

# Verify data integrity (example check, assuming a checksum file is maintained)
CHECKSUM_FILE="/var/lib/historical_node/checksums.txt"
if [ -f "$CHECKSUM_FILE" ]; then
    md5sum -c ${CHECKSUM_FILE} > /dev/null 2>&1
    if [ $? -ne 0 ]; then
        log_message "ERROR: Data integrity check failed for ${SERVICE_NAME}."
        exit 1
    fi
    log_message "Data integrity check passed for ${SERVICE_NAME}."
else
    log_message "WARNING: Checksum file not found. Skipping data integrity check."
fi

# Log the completion of the health check process
log_message "Health check for ${SERVICE_NAME} completed successfully."

exit 0
