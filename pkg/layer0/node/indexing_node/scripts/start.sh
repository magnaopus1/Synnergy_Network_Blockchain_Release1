#!/bin/bash

# start.sh - Script to start the Indexing Node

# Load configuration file
CONFIG_FILE="../config.toml"

# Function to parse configuration values
parse_config() {
    local key=$1
    grep -oP "(?<=${key} = \")[^\"]+" "$CONFIG_FILE"
}

# Get configuration values
NODE_HOST=$(parse_config "api_host")
NODE_PORT=$(parse_config "api_port")
LOG_DIR=$(parse_config "log_dir")
DATA_DIR=$(parse_config "data_dir")
API_KEY=$(parse_config "api_key")
INDEXING_SERVICE=$(parse_config "indexing_service")

# Check if necessary commands are available
check_command() {
    if ! command -v "$1" &> /dev/null; then
        echo "Error: $1 command not found. Please install $1 and try again."
        exit 1
    fi
}

# Ensure necessary commands are available
check_command "curl"
check_command "systemctl"

# Start the indexing service
echo "Starting the Indexing Node service..."

# Ensure log and data directories exist
mkdir -p "$LOG_DIR"
mkdir -p "$DATA_DIR"

# Start the service using systemctl
systemctl start "$INDEXING_SERVICE"

# Check the status of the service
service_status=$(systemctl is-active "$INDEXING_SERVICE")

if [ "$service_status" = "active" ]; then
    echo "Indexing Node service started successfully."
    exit 0
else
    echo "Failed to start Indexing Node service. Please check the logs for more details."
    exit 1
fi
