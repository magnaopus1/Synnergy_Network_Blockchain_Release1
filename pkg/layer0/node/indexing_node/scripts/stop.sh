#!/bin/bash

# stop.sh - Script to stop the Indexing Node

# Load configuration file
CONFIG_FILE="../config.toml"

# Function to parse configuration values
parse_config() {
    local key=$1
    grep -oP "(?<=${key} = \")[^\"]+" "$CONFIG_FILE"
}

# Get configuration values
LOG_DIR=$(parse_config "log_dir")
DATA_DIR=$(parse_config "data_dir")
INDEXING_SERVICE=$(parse_config "indexing_service")

# Check if necessary commands are available
check_command() {
    if ! command -v "$1" &> /dev/null; then
        echo "Error: $1 command not found. Please install $1 and try again."
        exit 1
    fi
}

# Ensure necessary commands are available
check_command "systemctl"

# Stop the indexing service
echo "Stopping the Indexing Node service..."

# Stop the service using systemctl
systemctl stop "$INDEXING_SERVICE"

# Check the status of the service
service_status=$(systemctl is-active "$INDEXING_SERVICE")

if [ "$service_status" = "inactive" ]; then
    echo "Indexing Node service stopped successfully."
    exit 0
else
    echo "Failed to stop Indexing Node service. Please check the logs for more details."
    exit 1
fi
