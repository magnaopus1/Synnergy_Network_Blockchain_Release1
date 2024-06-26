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

# Function to stop the Regulatory Node
stop_regulatory_node() {
  if [ ! -f "$REGULATORY_NODE_PID_FILE" ]; then
    echo "No PID file found. The Regulatory Node may not be running."
    exit 1
  fi

  # Read the PID from the file
  PID=$(cat "$REGULATORY_NODE_PID_FILE")

  # Check if the process is running
  if ps -p "$PID" > /dev/null; then
    echo "Stopping Regulatory Node (PID: $PID)..."
    kill -SIGTERM "$PID"
    
    # Wait for the process to terminate
    while ps -p "$PID" > /dev/null; do
      sleep 1
    done
    
    echo "Regulatory Node stopped."
    rm -f "$REGULATORY_NODE_PID_FILE"
  else
    echo "No process found with PID: $PID. Removing stale PID file."
    rm -f "$REGULATORY_NODE_PID_FILE"
  fi
}

# Function to ensure cleanup on exit
cleanup() {
  echo "Cleaning up resources..."
  # Add any additional cleanup tasks here
}

# Trap signals to ensure cleanup is performed
trap cleanup EXIT

# Execute the stop function
stop_regulatory_node

echo "Regulatory Node has been successfully stopped."
