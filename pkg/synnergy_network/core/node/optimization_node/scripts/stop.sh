#!/bin/bash

# Script to stop the Optimization Node
# This script ensures a graceful shutdown of the Optimization Node,
# performs necessary cleanup, and ensures data integrity.

NODE_NAME="OptimizationNode"
PID_FILE="/var/run/${NODE_NAME}.pid"
LOG_FILE="/var/log/${NODE_NAME}.log"
BACKUP_DIR="/var/backups/${NODE_NAME}"
DATA_DIR="/var/lib/${NODE_NAME}"

# Function to perform a graceful shutdown
shutdown_node() {
    if [ -f "$PID_FILE" ]; then
        PID=$(cat "$PID_FILE")
        echo "Stopping ${NODE_NAME} with PID ${PID}..."

        # Send SIGTERM to the process
        kill -15 "$PID"

        # Wait for the process to terminate
        while kill -0 "$PID" 2>/dev/null; do
            sleep 1
        done

        echo "${NODE_NAME} stopped successfully."
        rm -f "$PID_FILE"
    else
        echo "PID file not found. Is ${NODE_NAME} running?"
    fi
}

# Function to perform cleanup tasks
cleanup() {
    echo "Performing cleanup tasks..."

    # Backup data before cleanup
    TIMESTAMP=$(date +"%Y%m%d%H%M%S")
    BACKUP_FILE="${BACKUP_DIR}/${NODE_NAME}_backup_${TIMESTAMP}.tar.gz"

    echo "Creating backup of data directory ${DATA_DIR}..."
    tar -czf "$BACKUP_FILE" -C "$DATA_DIR" .

    # Verify backup success
    if [ $? -eq 0 ]; then
        echo "Backup created successfully at ${BACKUP_FILE}"
    else
        echo "Backup failed. Exiting cleanup."
        exit 1
    fi

    # Log cleanup
    echo "Clearing log file ${LOG_FILE}..."
    > "$LOG_FILE"

    echo "Cleanup completed."
}

# Function to ensure data integrity
ensure_data_integrity() {
    echo "Ensuring data integrity..."

    # Perform data integrity checks
    INTEGRITY_CHECK_RESULT=$(./integrity_check_tool --data-dir "$DATA_DIR")

    if [ "$INTEGRITY_CHECK_RESULT" == "OK" ]; then
        echo "Data integrity check passed."
    else
        echo "Data integrity check failed. Please investigate."
        exit 1
    fi
}

# Function to handle errors and ensure safe exit
handle_error() {
    echo "An error occurred. Performing safe exit."
    exit 1
}

# Main script execution
echo "Stopping ${NODE_NAME}..."

# Trap errors to ensure safe exit
trap 'handle_error' ERR

# Step-by-step execution
shutdown_node
ensure_data_integrity
cleanup

echo "${NODE_NAME} stopped and cleaned up successfully."

exit 0
