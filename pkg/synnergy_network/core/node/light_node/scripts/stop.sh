#!/bin/bash

# stop.sh
# This script is used to stop the Light Node for the Synthron blockchain

# Function to check if the Light Node process is running
check_node_process() {
    echo "Checking if the Light Node process is running..."
    if ! pgrep -f "light_node" > /dev/null; then
        echo "Light Node process is not running."
        exit 0
    fi
}

# Function to stop the Light Node process
stop_light_node() {
    echo "Stopping the Light Node..."
    pkill -f "light_node"
    if [ $? -eq 0 ]; then
        echo "Light Node stopped successfully."
    else
        echo "Failed to stop Light Node."
        exit 1
    fi
}

# Function to verify the Light Node process has stopped
verify_node_stopped() {
    echo "Verifying Light Node has stopped..."
    sleep 3
    if pgrep -f "light_node" > /dev/null; then
        echo "Light Node is still running."
        exit 1
    else
        echo "Light Node has stopped successfully."
    fi
}

# Main function to execute the stop process
main() {
    check_node_process
    stop_light_node
    verify_node_stopped
}

# Execute the main function
main
