#!/bin/bash

# Load environment variables from .env file if it exists
if [ -f ../.env ]; then
  export $(cat ../.env | xargs)
fi

# Ensure essential environment variables are set
if [ -z "$REGULATORY_NODE_PID_FILE" ]; then
  echo "Error: REGULATORY_NODE_PID_FILE environment variable is not set."
  exit 1
fi

if [ -z "$REGULATORY_NODE_LOG_DIR" ]; then
  echo "Error: REGULATORY_NODE_LOG_DIR environment variable is not set."
  exit 1
fi

if [ -z "$REGULATORY_NODE_BINARY" ]; then
  echo "Error: REGULATORY_NODE_BINARY environment variable is not set."
  exit 1
fi

# Check if the Regulatory Node process is running
check_process() {
  if [ -f "$REGULATORY_NODE_PID_FILE" ]; then
    PID=$(cat "$REGULATORY_NODE_PID_FILE")
    if ps -p "$PID" > /dev/null; then
      echo "Regulatory Node is running with PID: $PID"
    else
      echo "Error: Regulatory Node process not running, but PID file exists."
      return 1
    fi
  else
    echo "Error: PID file not found."
    return 1
  fi
}

# Check if the log file is being written to
check_logs() {
  LOG_FILE="$REGULATORY_NODE_LOG_DIR/regulatory_node.log"
  if [ -f "$LOG_FILE" ]; then
    if [ "$(tail -n 1 "$LOG_FILE" | grep -c 'ERROR')" -ne 0 ]; then
      echo "Error: Found errors in the log file."
      return 1
    fi
    echo "Log file check passed."
  else
    echo "Error: Log file not found."
    return 1
  fi
}

# Check network connectivity
check_network() {
  # Example: Check connectivity to a known service or peer node
  if ! ping -c 1 8.8.8.8 > /dev/null 2>&1; then
    echo "Error: Network connectivity issue."
    return 1
  fi
  echo "Network connectivity check passed."
}

# Check blockchain synchronization status
check_sync_status() {
  # Placeholder command; replace with actual command to check sync status
  SYNC_STATUS=$("$REGULATORY_NODE_BINARY" check-sync-status)
  if [ "$SYNC_STATUS" != "synced" ]; then
    echo "Error: Regulatory Node is not synchronized. Current status: $SYNC_STATUS"
    return 1
  fi
  echo "Blockchain synchronization check passed."
}

# Check disk space
check_disk_space() {
  USAGE=$(df -h "$REGULATORY_NODE_LOG_DIR" | tail -1 | awk '{print $5}' | sed 's/%//')
  if [ "$USAGE" -gt 80 ]; then
    echo "Error: Disk space usage is above 80%."
    return 1
  fi
  echo "Disk space check passed."
}

# Run all checks
run_health_checks() {
  check_process && check_logs && check_network && check_sync_status && check_disk_space
}

# Execute health checks
if run_health_checks; then
  echo "All health checks passed."
else
  echo "One or more health checks failed."
  exit 1
fi
