#!/bin/bash

# Define the path for the log file
LOGFILE="/var/log/synthron/ai_node_shutdown.log"
NODE_PROCESS_NAME="ai_node_process"

# Function to log messages
log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" >> $LOGFILE
}

# Gracefully stop the AI node
stop_node() {
    log "Attempting to stop AI-Enhanced Node."

    # Find the process ID of the AI node
    PID=$(pgrep -f $NODE_PROCESS_NAME)
    if [ -z "$PID" ]; then
        log "AI-Enhanced Node process not found. It may not be running."
    else
        # Send SIGTERM to allow graceful shutdown
        kill -SIGTERM "$PID"
        wait "$PID"
        log "AI-Enhanced Node stopped successfully."
    fi
}

# Check if any AI model training is currently active and try to terminate it gracefully
check_and_stop_model_training() {
    log "Checking for ongoing AI model training processes."
    TRAINING_PID=$(pgrep -f "model_training_script")
    if [ ! -z "$TRAINING_PID" ]; then
        log "Active model training process found. Attempting to stop it gracefully."
        kill -SIGTERM "$TRAINING_PID"
        wait "$TRAINING_PID"
        log "Model training process stopped successfully."
    else
        log "No active model training process found."
    fi
}

# Ensure all data has been synced to disk
sync_data() {
    log "Syncing data to disk."
    sync
}

# Main execution block
main() {
    log "Initiating shutdown sequence for AI-Enhanced Node."
    check_and_stop_model_training
    stop_node
    sync_data
    log "Shutdown sequence completed successfully."
}

# Execute the main function
main
