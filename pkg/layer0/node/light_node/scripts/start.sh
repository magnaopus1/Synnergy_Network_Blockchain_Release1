#!/bin/bash

# start.sh
# This script is used to start the Light Node for the Synthron blockchain

# Function to check if the Light Node process is already running
check_node_process() {
    echo "Checking if the Light Node process is already running..."
    if pgrep -f "light_node" > /dev/null; then
        echo "Light Node process is already running."
        exit 0
    fi
}

# Function to set environment variables
set_environment_variables() {
    echo "Setting environment variables..."
    export NODE_HOME="/usr/local/synthron/light_node"
    export NODE_CONFIG="$NODE_HOME/config.toml"
    export NODE_DATA="$NODE_HOME/data"
    export NODE_LOGS="$NODE_HOME/logs"
}

# Function to initialize the Light Node configuration
initialize_node_config() {
    echo "Initializing Light Node configuration..."
    if [ ! -f "$NODE_CONFIG" ]; then
        echo "Configuration file not found, creating default configuration..."
        cp "$NODE_HOME/config.default.toml" "$NODE_CONFIG"
    fi
}

# Function to create necessary directories
create_directories() {
    echo "Creating necessary directories..."
    mkdir -p "$NODE_DATA" "$NODE_LOGS"
}

# Function to start the Light Node
start_light_node() {
    echo "Starting the Light Node..."
    nohup ./light_node --config "$NODE_CONFIG" --data "$NODE_DATA" > "$NODE_LOGS/node.log" 2>&1 &
    if [ $? -eq 0 ]; then
        echo "Light Node started successfully."
    else
        echo "Failed to start Light Node."
        exit 1
    fi
}

# Function to check the status of the Light Node after startup
check_node_status() {
    echo "Checking Light Node status..."
    sleep 5
    if pgrep -f "light_node" > /dev/null; then
        echo "Light Node is running successfully."
    else
        echo "Light Node failed to start."
        exit 1
    fi
}

# Main function to execute the startup process
main() {
    check_node_process
    set_environment_variables
    initialize_node_config
    create_directories
    start_light_node
    check_node_status
}

# Execute the main function
main
