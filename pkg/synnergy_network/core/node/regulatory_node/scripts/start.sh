#!/bin/bash

# Load environment variables from .env file if it exists
if [ -f ../.env ]; then
  export $(cat ../.env | xargs)
fi

# Ensure essential environment variables are set
if [ -z "$REGULATORY_NODE_LOG_DIR" ]; then
  echo "Error: REGULATORY_NODE_LOG_DIR environment variable is not set."
  exit 1
fi

if [ -z "$REGULATORY_NODE_PID_FILE" ]; then
  echo "Error: REGULATORY_NODE_PID_FILE environment variable is not set."
  exit 1
fi

if [ -z "$REGULATORY_NODE_BINARY" ]; then
  echo "Error: REGULATORY_NODE_BINARY environment variable is not set."
  exit 1
fi

# Create log directory if it doesn't exist
mkdir -p "$REGULATORY_NODE_LOG_DIR"

# Function to start the Regulatory Node
start_regulatory_node() {
  # Check if the Regulatory Node is already running
  if [ -f "$REGULATORY_NODE_PID_FILE" ]; then
    PID=$(cat "$REGULATORY_NODE_PID_FILE")
    if ps -p "$PID" > /dev/null; then
      echo "Regulatory Node is already running with PID: $PID"
      exit 1
    else
      echo "Stale PID file found. Removing it."
      rm -f "$REGULATORY_NODE_PID_FILE"
    fi
  fi

  # Start the Regulatory Node
  echo "Starting Regulatory Node..."
  nohup "$REGULATORY_NODE_BINARY" > "$REGULATORY_NODE_LOG_DIR/regulatory_node.log" 2>&1 &
  
  # Save the PID of the started process
  PID=$!
  echo "$PID" > "$REGULATORY_NODE_PID_FILE"
  echo "Regulatory Node started with PID: $PID"
}

# Function to ensure cleanup on exit
cleanup() {
  echo "Cleaning up resources..."
  # Add any additional cleanup tasks here
}

# Trap signals to ensure cleanup is performed
trap cleanup EXIT

# Execute the start function
start_regulatory_node

echo "Regulatory Node has been successfully started."
