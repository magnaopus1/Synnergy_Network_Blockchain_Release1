#!/bin/bash

# Load environment variables
source /path/to/.env

# Function to start the node
start_node() {
    echo "Starting Experimental Node..."

    # Check if the node is already running
    NODE_PID=$(pgrep -f experimental_node)
    if [ -n "$NODE_PID" ]; then
        echo "Experimental Node is already running with PID: $NODE_PID"
        exit 0
    fi

    # Start the Experimental Node process
    nohup /path/to/experimental_node > /path/to/logs/experimental_node.log 2>&1 &

    # Verify the node has started
    sleep 5
    NODE_PID=$(pgrep -f experimental_node)
    if [ -n "$NODE_PID" ]; then
        echo "Experimental Node started successfully with PID: $NODE_PID"
    else
        echo "Failed to start Experimental Node."
        exit 1
    fi

    # Perform any necessary setup operations
    setup_operations
}

# Function to perform necessary setup operations
setup_operations() {
    echo "Performing setup operations..."

    # Ensure that all necessary services are started
    start_associated_services

    # Check for blockchain synchronization
    check_blockchain_sync

    echo "Setup operations completed."
}

# Function to start associated services
start_associated_services() {
    echo "Starting associated services..."

    # Example: Start a service associated with the node
    if ! systemctl is-active --quiet some_service; then
        systemctl start some_service
        echo "Started some_service."
    fi

    echo "Associated services started."
}

# Function to check blockchain synchronization
check_blockchain_sync() {
    echo "Checking blockchain synchronization..."

    SYNC_STATUS=$(curl -s http://localhost:PORT/sync_status)
    while [ "$SYNC_STATUS" != "synced" ]; do
        echo "Node is not yet synchronized. Current status: $SYNC_STATUS"
        sleep 10
        SYNC_STATUS=$(curl -s http://localhost:PORT/sync_status)
    done

    echo "Node is fully synchronized."
}

# Main script execution
start_node
