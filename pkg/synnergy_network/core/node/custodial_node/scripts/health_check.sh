#!/bin/bash

# Script to perform a health check on the Custodial Node and its related services

# Load environment variables
source /app/.env

# Function to check if a process is running based on its PID file
check_process() {
    local pid_file="$1"
    local service_name="$2"

    if [ -f "$pid_file" ]; then
        local pid=$(cat "$pid_file")
        if [ -d /proc/"$pid" ]; then
            echo "$service_name is running with PID $pid."
        else
            echo "Error: $service_name is not running. PID file exists but process is not found."
            return 1
        fi
    else
        echo "Error: $service_name is not running. PID file does not exist."
        return 1
    fi
}

# Function to check service health via HTTP
check_http_service() {
    local url="$1"
    local service_name="$2"
    local response=$(curl --write-out %{http_code} --silent --output /dev/null "$url")

    if [ "$response" -eq 200 ]; then
        echo "$service_name HTTP check passed (HTTP 200)."
    else
        echo "Error: $service_name HTTP check failed (HTTP $response)."
        return 1
    fi
}

# Function to perform a disk space check
check_disk_space() {
    local threshold="$1"
    local used_space=$(df /app | tail -1 | awk '{print $5}' | sed 's/%//')

    if [ "$used_space" -lt "$threshold" ]; then
        echo "Disk space usage is within limits: $used_space% used."
    else
        echo "Error: Disk space usage is high: $used_space% used."
        return 1
    fi
}

# Check the main Custodial Node process
check_process "$CUSTODIAL_NODE_PID_FILE" "Custodial Node"

# Check related services (example services)
related_services=("service1" "service2" "service3")  # Replace with actual service names

for service in "${related_services[@]}"; do
    service_pid_file="/var/run/${service}.pid"
    check_process "$service_pid_file" "$service"
done

# Check HTTP services (example endpoints)
http_services=("http://localhost:8080/health" "http://localhost:9090/status")  # Replace with actual URLs

for url in "${http_services[@]}"; do
    service_name=$(echo "$url" | awk -F/ '{print $3}')
    check_http_service "$url" "$service_name"
done

# Perform disk space check with a threshold of 80%
check_disk_space 80

# Final confirmation
echo "All health checks completed."

# Exit with the appropriate status code
if [ $? -eq 0 ]; then
    echo "Custodial Node and related services are healthy."
    exit 0
else
    echo "One or more health checks failed."
    exit 1
fi
