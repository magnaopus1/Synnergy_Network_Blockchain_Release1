#!/bin/bash

# Integration Node Stop Script
# This script stops the Integration Node for the Synthron blockchain

# Function to log messages
log() {
    local MESSAGE=$1
    echo "$(date +"%Y-%m-%d %H:%M:%S") - ${MESSAGE}"
}

# Load environment variables from .env file
log "Loading environment variables..."
if [ -f .env ]; then
    export $(cat .env | xargs)
else
    log "Error: .env file not found."
    exit 1
fi

# Define the process name or port for the Integration Node
INTEGRATION_NODE_PROCESS_NAME="integration_node"
INTEGRATION_NODE_PORT=${INTEGRATION_NODE_PORT:-8080}

# Function to stop the process by name
stop_process_by_name() {
    local PROCESS_NAME=$1
    PID=$(pgrep -f ${PROCESS_NAME})
    if [ -z "$PID" ]; then
        log "No process found with name ${PROCESS_NAME}."
    else
        log "Stopping process ${PROCESS_NAME} with PID ${PID}..."
        kill -SIGTERM $PID
        log "Process ${PROCESS_NAME} stopped."
    fi
}

# Function to stop the process by port
stop_process_by_port() {
    local PORT=$1
    PID=$(lsof -t -i:${PORT})
    if [ -z "$PID" ]; then
        log "No process found running on port ${PORT}."
    else
        log "Stopping process running on port ${PORT} with PID ${PID}..."
        kill -SIGTERM $PID
        log "Process running on port ${PORT} stopped."
    fi
}

# Check if the Integration Node is running by process name or port and stop it
if [ -n "$INTEGRATION_NODE_PROCESS_NAME" ]; then
    stop_process_by_name ${INTEGRATION_NODE_PROCESS_NAME}
fi

if [ -n "$INTEGRATION_NODE_PORT" ]; then
    stop_process_by_port ${INTEGRATION_NODE_PORT}
fi

log "Integration Node stopped successfully."

exit 0
