#!/bin/bash

# Audit Node Stop Script
# This script is designed to stop the audit node and ensure that all necessary cleanup operations are performed.
# It ensures that the node stops gracefully and all relevant services are halted.

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

# Function to stop the audit node process
stop_audit_node() {
  log "Stopping Audit Node..." "INFO"
  # Get the PID of the audit node process
  AUDIT_NODE_PID=$(pgrep -f "audit_node")
  
  if [ -z "$AUDIT_NODE_PID" ]; then
    log "No running audit node process found." "WARN"
  else
    # Kill the process
    kill -SIGTERM $AUDIT_NODE_PID
    log "Sent SIGTERM to Audit Node process (PID: $AUDIT_NODE_PID)" "INFO"
    
    # Wait for the process to terminate
    sleep 5
    
    # Check if the process has terminated
    if ps -p $AUDIT_NODE_PID > /dev/null; then
      log "Audit Node process did not terminate, sending SIGKILL..." "ERROR"
      kill -SIGKILL $AUDIT_NODE_PID
      log "Sent SIGKILL to Audit Node process (PID: $AUDIT_NODE_PID)" "INFO"
    else
      log "Audit Node process terminated successfully." "INFO"
    fi
  fi
}

# Function to stop additional services used by the audit node
stop_additional_services() {
  log "Stopping additional services..." "INFO"
  # Example: Stop a database service
  if [ -n "$(command -v systemctl)" ]; then
    systemctl stop audit_node_db
    log "Stopped audit_node_db service." "INFO"
  fi
  # Add other services as needed
}

# Function to clean up temporary files
cleanup_temp_files() {
  log "Cleaning up temporary files..." "INFO"
  # Example: Remove temporary files
  rm -rf /tmp/audit_node_*
  log "Temporary files cleaned up." "INFO"
}

# Function to perform final checks and log status
final_checks() {
  log "Performing final checks..." "INFO"
  # Check if the node has stopped
  if pgrep -f "audit_node" > /dev/null; then
    log "Audit Node process is still running!" "ERROR"
  else
    log "Audit Node has been stopped successfully." "INFO"
  fi
}

# Main script execution
log "Executing Audit Node stop script..." "INFO"
stop_audit_node
stop_additional_services
cleanup_temp_files
final_checks
log "Audit Node stop script execution completed." "INFO"
