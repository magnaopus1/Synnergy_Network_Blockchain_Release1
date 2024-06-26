#!/bin/bash

# Load environment variables
source /path/to/.env

# Function to stop the node gracefully
stop_node() {
    echo "Stopping Experimental Node..."

    # Check if the node is running
    NODE_PID=$(pgrep -f experimental_node)
    if [ -z "$NODE_PID" ]; {
        echo "No Experimental Node process found."
    } else {
        # Send SIGTERM to the node process to allow it to shutdown gracefully
        kill -SIGTERM "$NODE_PID"
        echo "Sent SIGTERM to Experimental Node process with PID: $NODE_PID"

        # Wait for the process to terminate
        wait "$NODE_PID"
        echo "Experimental Node process stopped successfully."
    }

    # Perform any necessary cleanup operations
    cleanup_operations
}

# Function to perform necessary cleanup operations
cleanup_operations() {
    echo "Performing cleanup operations..."

    # Remove temporary files
    rm -rf /path/to/temp_files/*
    echo "Temporary files removed."

    # Ensure that all services associated with the node are stopped
    stop_associated_services

    # Archive logs if necessary
    archive_logs

    echo "Cleanup operations completed."
}

# Function to stop associated services
stop_associated_services() {
    echo "Stopping associated services..."

    # Example: Stop a service associated with the node
    if systemctl is-active --quiet some_service; then
        systemctl stop some_service
        echo "Stopped some_service."
    fi

    echo "Associated services stopped."
}

# Function to archive logs
archive_logs() {
    echo "Archiving logs..."

    TIMESTAMP=$(date +"%Y%m%d%H%M%S")
    tar -czvf /path/to/logs/experimental_node_logs_$TIMESTAMP.tar.gz /path/to/logs/*.log
    echo "Logs archived with timestamp: $TIMESTAMP."

    echo "Log archiving completed."
}

# Main script execution
stop_node

