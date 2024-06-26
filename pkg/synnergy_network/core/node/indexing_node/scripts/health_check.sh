#!/bin/bash

# health_check.sh - Script to perform a comprehensive health check on the Indexing Node

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
API_KEY=$(parse_config "api_key")
HEALTH_CHECK_ENDPOINT=$(parse_config "health_check_endpoint")

# Check if necessary commands are available
check_command() {
    if ! command -v "$1" &> /dev/null; then
        echo "Error: $1 command not found. Please install $1 and try again."
        exit 1
    fi
}

# Ensure curl is available
check_command "curl"

# Perform health check
response=$(curl -s -o /dev/null -w "%{http_code}" -H "API-Key: $API_KEY" "$HEALTH_CHECK_ENDPOINT")

# Check response status
if [ "$response" -eq 200 ]; then
    echo "Indexing Node Health Check: SUCCESS"
    exit 0
else
    echo "Indexing Node Health Check: FAILED (HTTP Status: $response)"
    exit 1
fi
