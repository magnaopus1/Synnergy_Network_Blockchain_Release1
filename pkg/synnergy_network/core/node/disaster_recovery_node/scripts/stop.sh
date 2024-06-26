#!/bin/bash

# Script to stop the Disaster Recovery Node

# Load environment variables
if [ -f .env ]; then
  export $(cat .env | xargs)
fi

# Function to stop the disaster recovery node gracefully
stop_node() {
  NODE_PID_FILE="${DATA_DIR}/node.pid"

  if [ ! -f "$NODE_PID_FILE" ]; then
    echo "No PID file found. Is the node running?"
    exit 1
  fi

  NODE_PID=$(cat "$NODE_PID_FILE")
  echo "Stopping Disaster Recovery Node with PID: $NODE_PID"

  # Sending SIGTERM to the process to stop it gracefully
  kill -SIGTERM "$NODE_PID"

  # Wait for the process to terminate
  TIMEOUT=30
  while kill -0 "$NODE_PID" 2>/dev/null; do
    if [ $TIMEOUT -le 0 ]; then
      echo "Node did not stop gracefully, forcefully stopping it"
      kill -SIGKILL "$NODE_PID"
      break
    fi
    sleep 1
    TIMEOUT=$((TIMEOUT - 1))
  done

  # Clean up
  rm -f "$NODE_PID_FILE"
  echo "Disaster Recovery Node stopped successfully"
}

# Function to check if the node is running
is_node_running() {
  NODE_PID_FILE="${DATA_DIR}/node.pid"
  if [ -f "$NODE_PID_FILE" ]; then
    NODE_PID=$(cat "$NODE_PID_FILE")
    if kill -0 "$NODE_PID" 2>/dev/null; then
      return 0
    fi
  fi
  return 1
}

# Main script execution
if is_node_running; then
  stop_node
else
  echo "Disaster Recovery Node is not running."
fi
