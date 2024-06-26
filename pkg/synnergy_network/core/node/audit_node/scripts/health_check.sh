#!/bin/bash

# Audit Node Health Check Script
# This script is designed to check the health and status of the audit node, ensuring all necessary services are running and the node is operating correctly.

# Load environment variables from .env file if it exists
if [ -f .env ]; then
  export $(cat .env | xargs)
fi

# Function to log messages
log() {
  local message=$1
  local level=$2
  local timestamp=$(date +"%Y-%m-%d %H:%M:%S")
  echo "${timestamp} [${level}] ${message}"
}

# Function to check if a command exists
command_exists() {
  command -v "$1" >/dev/null 2>&1
}

# Function to check the status of the audit node process
check_audit_node() {
  local pid=$(pgrep -f audit_node)
  if [ -z "$pid" ]; then
    log "Audit Node process is not running." "ERROR"
    return 1
  else
    log "Audit Node process is running with PID: $pid" "INFO"
    return 0
  fi
}

# Function to check the status of the database service
check_db_service() {
  if command_exists systemctl; then
    systemctl is-active --quiet audit_node_db
    if [ $? -eq 0 ]; then
      log "Database service audit_node_db is active." "INFO"
      return 0
    else
      log "Database service audit_node_db is not active." "ERROR"
      return 1
    fi
  else
    log "Systemctl not found. Skipping database service check." "WARNING"
    return 2
  fi
}

# Function to check network connectivity
check_network() {
  if ping -c 1 8.8.8.8 &>/dev/null; then
    log "Network connectivity is active." "INFO"
    return 0
  else
    log "Network connectivity is inactive." "ERROR"
    return 1
  fi
}

# Function to check disk space
check_disk_space() {
  local threshold=80
  local usage=$(df / | tail -1 | awk '{print $5}' | sed 's/%//')
  if [ "$usage" -lt "$threshold" ]; then
    log "Disk space usage is within acceptable limits: ${usage}% used." "INFO"
    return 0
  else
    log "Disk space usage is above threshold: ${usage}% used." "ERROR"
    return 1
  fi
}

# Function to check memory usage
check_memory_usage() {
  local threshold=90
  local usage=$(free | grep Mem | awk '{print $3/$2 * 100.0}')
  if (( $(echo "$usage < $threshold" | bc -l) )); then
    log "Memory usage is within acceptable limits: ${usage}% used." "INFO"
    return 0
  else
    log "Memory usage is above threshold: ${usage}% used." "ERROR"
    return 1
  fi
}

# Main health check execution
log "Executing Audit Node health check script..." "INFO"
check_audit_node
audit_node_status=$?
check_db_service
db_service_status=$?
check_network
network_status=$?
check_disk_space
disk_space_status=$?
check_memory_usage
memory_usage_status=$?

# Aggregate results
if [ $audit_node_status -eq 0 ] && [ $db_service_status -eq 0 ] && [ $network_status -eq 0 ] && [ $disk_space_status -eq 0 ] && [ $memory_usage_status -eq 0 ]; then
  log "Audit Node health check passed. All systems are operational." "INFO"
  exit 0
else
  log "Audit Node health check failed. Please investigate the errors." "ERROR"
  exit 1
fi
