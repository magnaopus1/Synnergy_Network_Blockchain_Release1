#!/bin/bash

# Script to start the Custodial Node safely and securely

# Load environment variables
source /app/.env

# Function to start a process and save its PID
start_process() {
    local command="$1"
    local pid_file="$2"

    echo "Starting process: $command"
    nohup $command > /dev/null 2>&1 &
    local pid=$!
    echo $pid > "$pid_file"
    echo "Process started with PID $pid and saved to $pid_file."
}

# Function to check if a process is already running
is_process_running() {
    local pid_file="$1"

    if [ -f "$pid_file" ]; then
        local pid=$(cat "$pid_file")
        if [ -d /proc/"$pid" ]; then
            return 0
        fi
    fi
    return 1
}

# Ensure the necessary directories exist
mkdir -p "$CUSTODIAL_NODE_DATA_DIR"
mkdir -p "$CUSTODIAL_NODE_LOG_DIR"

# Check if Custodial Node is already running
if is_process_running "$CUSTODIAL_NODE_PID_FILE"; then
    echo "Custodial Node is already running."
    exit 0
fi

# Start the Custodial Node process
start_process "$CUSTODIAL_NODE_COMMAND" "$CUSTODIAL_NODE_PID_FILE"

# Ensure related services are started
related_services=("service1" "service2" "service3")  # Replace with actual service names

for service in "${related_services[@]}"; do
    service_command_var="${service^^}_COMMAND"
    service_pid_file="/var/run/${service}.pid"

    if is_process_running "$service_pid_file"; then
        echo "$service is already running."
    else
        start_process "${!service_command_var}" "$service_pid_file"
    fi
done

# Perform any additional startup tasks
echo "Performing additional startup tasks..."
# Add any necessary startup commands here

# Final confirmation
echo "Custodial Node and related services have been started successfully."
