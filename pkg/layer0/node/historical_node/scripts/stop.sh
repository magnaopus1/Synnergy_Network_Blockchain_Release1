#!/bin/bash

# stop.sh - Script to stop the Historical Node

# Define the service name
SERVICE_NAME="historical_node"

# Define the log file location
LOG_FILE="/var/log/historical_node/stop.log"

# Function to log messages
log_message() {
    local MESSAGE=$1
    echo "$(date '+%Y-%m-%d %H:%M:%S') - ${MESSAGE}" | tee -a ${LOG_FILE}
}

# Log the start of the shutdown process
log_message "Initiating shutdown process for ${SERVICE_NAME}."

# Check if the node is running
PID=$(pgrep -f ${SERVICE_NAME})
if [ -z "$PID" ]; then
    log_message "No running process found for ${SERVICE_NAME}."
    exit 0
fi

# Gracefully stop the node
log_message "Stopping ${SERVICE_NAME} with PID ${PID}."
kill -SIGTERM ${PID}

# Wait for the process to terminate
TIMEOUT=60
while [ ${TIMEOUT} -gt 0 ]; do
    if ! kill -0 ${PID} > /dev/null 2>&1; then
        log_message "${SERVICE_NAME} stopped successfully."
        exit 0
    fi
    sleep 1
    TIMEOUT=$((TIMEOUT-1))
done

# Force kill if the process did not stop within the timeout period
log_message "${SERVICE_NAME} did not stop within the timeout period. Force killing..."
kill -SIGKILL ${PID}

# Verify if the process is killed
if ! kill -0 ${PID} > /dev/null 2>&1; then
    log_message "${SERVICE_NAME} force killed successfully."
else
    log_message "Failed to stop ${SERVICE_NAME}. Please check manually."
    exit 1
fi

# Log the completion of the shutdown process
log_message "Shutdown process for ${SERVICE_NAME} completed."

exit 0
