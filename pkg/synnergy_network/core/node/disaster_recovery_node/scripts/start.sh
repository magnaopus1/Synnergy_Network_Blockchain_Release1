#!/bin/bash

# Script to start the Disaster Recovery Node

# Load environment variables
if [ -f .env ]; then
  export $(cat .env | xargs)
fi

# Function to start the disaster recovery node
start_node() {
  echo "Starting Disaster Recovery Node..."

  # Check if the node is already running
  NODE_PID_FILE="${DATA_DIR}/node.pid"
  if [ -f "$NODE_PID_FILE" ]; then
    NODE_PID=$(cat "$NODE_PID_FILE")
    if kill -0 "$NODE_PID" 2>/dev/null; then
      echo "Node is already running with PID: $NODE_PID"
      exit 1
    else
      echo "Found stale PID file. Removing..."
      rm -f "$NODE_PID_FILE"
    fi
  fi

  # Start the node and save the PID
  ./disaster_recovery_node > "${LOG_DIR}/node.log" 2>&1 &
  NODE_PID=$!
  echo $NODE_PID > "$NODE_PID_FILE"
  echo "Disaster Recovery Node started with PID: $NODE_PID"
}

# Ensure necessary directories exist
mkdir -p "${DATA_DIR}"
mkdir -p "${LOG_DIR}"

# Main script execution
start_node
