#!/bin/bash

# Script to stop the Custodial Node safely and securely

# Load environment variables
source /app/.env

# Function to check if a process is running
is_process_running() {
    local pid="$1"
    if [ -d /proc/"$pid" ]; then
        return 0
    else
        return 1
    fi
}

# Function to stop a process by its PID
stop_process() {
    local pid="$1"
    if is_process_running "$pid"; then
        echo "Stopping process with PID $pid..."
        kill "$pid"
        # Wait for the process to terminate
        while is_process_running "$pid"; do
            sleep 1
        done
        echo "Process with PID $pid has been stopped."
    else
        echo "No running process found with PID $pid."
    fi
}

# Load the PID of the Custodial Node
if [ -f "$CUSTODIAL_NODE_PID_FILE" ]; then
    CUSTODIAL_NODE_PID=$(cat "$CUSTODIAL_NODE_PID_FILE")
    stop_process "$CUSTODIAL_NODE_PID"
    rm -f "$CUSTODIAL_NODE_PID_FILE"
else
    echo "PID file for Custodial Node not found. Is the node running?"
fi

# Ensure all related services are stopped
related_services=("service1" "service2" "service3")  # Replace with actual service names

for service in "${related_services[@]}"; do
    if [ -f "/var/run/$service.pid" ]; then
        SERVICE_PID=$(cat "/var/run/$service.pid")
        stop_process "$SERVICE_PID"
        rm -f "/var/run/$service.pid"
    else
        echo "PID file for $service not found. Is the service running?"
    fi
done

# Perform any cleanup tasks
echo "Performing cleanup tasks..."
# Add any necessary cleanup commands here

# Final confirmation
echo "Custodial Node and related services have been stopped."
