#!/bin/bash

# Integration Node Health Check Script
# This script performs health checks on the Integration Node for the Synthron blockchain

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

# Function to check if a service is running
check_service_running() {
    local SERVICE_NAME=$1
    local SERVICE_PID=$(pgrep -f ${SERVICE_NAME})
    if [ -z "$SERVICE_PID" ]; then
        log "Service ${SERVICE_NAME} is not running."
        return 1
    else
        log "Service ${SERVICE_NAME} is running with PID ${SERVICE_PID}."
        return 0
    fi
}

# Function to perform a simple API check
check_api() {
    local API_URL=$1
    local RESPONSE_CODE=$(curl -s -o /dev/null -w "%{http_code}" ${API_URL})
    if [ "$RESPONSE_CODE" -eq 200 ]; then
        log "API ${API_URL} is responding with status code 200."
        return 0
    else
        log "API ${API_URL} is not responding correctly. Status code: ${RESPONSE_CODE}"
        return 1
    fi
}

# Check if the Integration Node service is running
check_service_running "integration_node"
NODE_RUNNING=$?

# Perform a health check on the Integration Node API
INTEGRATION_NODE_API_URL="http://localhost:${INTEGRATION_NODE_API_PORT}/health"
check_api ${INTEGRATION_NODE_API_URL}
API_HEALTHY=$?

# Evaluate the health check results
if [ $NODE_RUNNING -eq 0 ] && [ $API_HEALTHY -eq 0 ]; then
    log "Integration Node health check passed."
    exit 0
else
    log "Integration Node health check failed."
    exit 1
fi
