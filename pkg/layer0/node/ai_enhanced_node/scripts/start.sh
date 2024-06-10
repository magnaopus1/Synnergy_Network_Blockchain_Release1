#!/bin/bash

# Define the path for the log file and node application
LOGFILE="/var/log/synthron/ai_node_startup.log"
NODE_APP_PATH="/usr/local/synthron/ai_enhanced_node"
AI_MODEL_PATH="/opt/synthron/ai_models"

# Function to log messages
log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" >> $LOGFILE
}

# Check if the necessary directories exist
check_directories() {
    log "Checking necessary directories."
    if [ ! -d "$AI_MODEL_PATH" ]; then
        log "AI model directory not found. Attempting to create."
        mkdir -p "$AI_MODEL_PATH" || { log "Failed to create model directory."; exit 1; }
    fi
    log "All necessary directories are present."
}

# Ensure the AI model is in place
check_ai_model() {
    log "Checking for AI model availability."
    if [ ! -f "$AI_MODEL_PATH/predictive_analytics_model.pt" ]; then
        log "AI model is missing. Cannot start the node without the AI model."
        exit 1
    fi
    log "AI model is in place."
}

# Start the node application
start_node() {
    log "Starting the AI-Enhanced Node."
    cd "$NODE_APP_PATH"
    if ! ./node; then
        log "Failed to start the AI-Enhanced Node."
        exit 1
    fi
    log "AI-Enhanced Node started successfully."
}

# Main execution block
main() {
    log "Initiating startup sequence for AI-Enhanced Node."
    check_directories
    check_ai_model
    start_node
    log "Startup sequence completed."
}

# Execute the main function
main
