#!/bin/bash

# Audit Node Start Script
# This script is designed to start the audit node and ensure all necessary initialization and setup operations are performed.

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

# Function to start the audit node process
start_audit_node() {
  log "Starting Audit Node..." "INFO"
  
  # Start the audit node process
  nohup ./audit_node > audit_node.log 2>&1 &
  
  if [ $? -eq 0 ]; then
    log "Audit Node started successfully." "INFO"
  else
    log "Failed to start Audit Node." "ERROR"
    exit 1
  fi
}

# Function to start additional services used by the audit node
start_additional_services() {
  log "Starting additional services..." "INFO"
  
  # Example: Start a database service
  if command_exists systemctl; then
    systemctl start audit_node_db
    if [ $? -eq 0 ]; then
      log "Started audit_node_db service." "INFO"
    else
      log "Failed to start audit_node_db service." "ERROR"
      exit 1
    fi
  fi
  # Add other services as needed
}

# Function to initialize required directories and files
initialize_directories() {
  log "Initializing directories and files..." "INFO"
  
  # Create necessary directories
  mkdir -p /var/log/synthron_audit_node /var/lib/synthron_audit_node
  
  # Set permissions
  chmod 700 /var/log/synthron_audit_node /var/lib/synthron_audit_node
  
  # Create a log file if it does not exist
  touch /var/log/synthron_audit_node/audit_node.log
}

# Function to perform initial checks and setup
initial_checks() {
  log "Performing initial checks..." "INFO"
  
  # Check if necessary environment variables are set
  if [ -z "$AUDIT_NODE_ENV" ]; then
    log "Environment variable AUDIT_NODE_ENV is not set." "ERROR"
    exit 1
  fi

  # Check if the audit node binary exists
  if [ ! -f "./audit_node" ]; then
    log "Audit node binary not found." "ERROR"
    exit 1
  fi
}

# Main script execution
log "Executing Audit Node start script..." "INFO"
initial_checks
initialize_directories
start_additional_services
start_audit_node
log "Audit Node start script execution completed." "INFO"
