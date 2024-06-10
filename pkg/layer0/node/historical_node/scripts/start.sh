#!/bin/bash

# start.sh - Script to start the Historical Node

# Define the service name
SERVICE_NAME="historical_node"

# Define the log file location
LOG_FILE="/var/log/historical_node/start.log"

# Function to log messages
log_message() {
    local MESSAGE=$1
    echo "$(date '+%Y-%m-%d %H:%M:%S') - ${MESSAGE}" | tee -a ${LOG_FILE}
}

# Log the start of the startup process
log_message "Initiating startup process for ${SERVICE_NAME}."

# Check if the node is already running
PID=$(pgrep -f ${SERVICE_NAME})
if [ -n "$PID" ]; then
    log_message "${SERVICE_NAME} is already running with PID ${PID}."
    exit 0
fi

# Set environment variables and configurations
export NODE_ENV="production"
export CONFIG_FILE="/etc/historical_node/config.toml"
log_message "Environment variables and configurations set."

# Start the historical node process
nohup /usr/local/bin/${SERVICE_NAME} --config ${CONFIG_FILE} >> ${LOG_FILE} 2>&1 &

# Wait briefly to ensure the node has started
sleep 5

# Verify that the node has started
PID=$(pgrep -f ${SERVICE_NAME})
if [ -n "$PID" ]; then
    log_message "${SERVICE_NAME} started successfully with PID ${PID}."
else
    log_message "Failed to start ${SERVICE_NAME}. Please check the logs for more details."
    exit 1
fi

# Log the completion of the startup process
log_message "Startup process for ${SERVICE_NAME} completed."

exit 0
