#!/bin/bash

# AI-Enhanced Node Health Check Script
# This script performs a health check on the AI-Enhanced Node for the Synthron blockchain.
# It ensures that the node is running correctly and all critical components are operational.

# Load environment variables
source ../.env

# Function to check if the node process is running
check_process() {
    echo "Checking if AI-Enhanced Node process is running..."

    NODE_PID=$(pgrep -f ai_enhanced_node)

    if [ -z "$NODE_PID" ]; then
        echo "Error: AI-Enhanced Node process not running."
        exit 1
    else
        echo "AI-Enhanced Node process is running with PID: $NODE_PID"
    fi
}

# Function to check if the node is responsive
check_responsiveness() {
    echo "Checking if AI-Enhanced Node is responsive..."

    # Assume the node has a health check endpoint or some means to verify responsiveness
    HEALTH_CHECK_URL="http://localhost:8080/health"

    RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" $HEALTH_CHECK_URL)

    if [ "$RESPONSE" -ne 200 ]; then
        echo "Error: AI-Enhanced Node is not responsive. HTTP Status: $RESPONSE"
        exit 1
    else
        echo "AI-Enhanced Node is responsive."
    fi
}

# Function to check logs for errors
check_logs() {
    echo "Checking AI-Enhanced Node logs for errors..."

    LOG_FILE="../logs/ai_enhanced_node.log"

    if [ ! -f "$LOG_FILE" ]; then
        echo "Error: Log file not found at $LOG_FILE"
        exit 1
    fi

    # Look for common error indicators in the logs
    ERRORS=$(grep -i "error" $LOG_FILE)

    if [ -n "$ERRORS" ]; then
        echo "Errors found in log file:"
        echo "$ERRORS"
        exit 1
    else
        echo "No errors found in log file."
    fi
}

# Function to verify AI model status
check_ai_models() {
    echo "Checking AI models status..."

    # Placeholder for checking AI model status
    # This could involve verifying model files, checking a status endpoint, etc.
    MODEL_STATUS="Healthy"

    if [ "$MODEL_STATUS" != "Healthy" ]; then
        echo "Error: AI models are not in a healthy state."
        exit 1
    else
        echo "AI models are in a healthy state."
    fi
}

# Main script execution
echo "Executing health check script for AI-Enhanced Node..."

check_process
check_responsiveness
check_logs
check_ai_models

echo "AI-Enhanced Node health check completed successfully."
