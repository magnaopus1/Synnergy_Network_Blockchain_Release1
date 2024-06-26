#!/bin/bash

# Integration Node Start Script
# This script starts the Integration Node for the Synthron blockchain

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

# Define the binary or script to start the Integration Node
INTEGRATION_NODE_BINARY="./integration_node"

# Function to start the Integration Node
start_integration_node() {
    log "Starting the Integration Node..."
    nohup ${INTEGRATION_NODE_BINARY} > logs/integration_node.log 2>&1 &
    if [ $? -eq 0 ]; then
        log "Integration Node started successfully."
    else
        log "Failed to start Integration Node."
        exit 1
    fi
}

# Ensure the logs directory exists
mkdir -p logs

# Check if the Integration Node is already running
PID=$(pgrep -f ${INTEGRATION_NODE_BINARY})
if [ -n "$PID" ]; then
    log "Integration Node is already running with PID ${PID}."
    exit 0
else
    start_integration_node
fi

log "Integration Node start process completed."

exit 0
