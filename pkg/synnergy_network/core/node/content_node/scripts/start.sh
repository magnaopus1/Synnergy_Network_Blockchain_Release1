#!/bin/bash

# Start script for Content Node

# Load environment variables
if [ -f .env ]; then
  export $(cat .env | xargs)
fi

# Function to start the Content Node service
start_content_node() {
  echo "Starting Content Node service..."

  # Check if the node is already running
  PID=$(ps -ef | grep content_node | grep -v grep | awk '{print $2}')
  if [ ! -z "$PID" ]; then
    echo "Content Node service is already running (PID: $PID)."
    return
  fi

  # Ensure necessary directories exist
  mkdir -p "$CONTENT_NODE_LOG_DIR"
  mkdir -p "$CONTENT_NODE_DATA_DIR"
  mkdir -p "$CONTENT_NODE_TMP_DIR"

  # Start the content node service in the background
  nohup ./content_node > "$CONTENT_NODE_LOG_DIR/content_node.log" 2>&1 &

  # Get the PID of the newly started service
  PID=$!
  echo "Content Node service started (PID: $PID). Log output is redirected to $CONTENT_NODE_LOG_DIR/content_node.log"
}

# Function to ensure required directories exist
ensure_directories() {
  echo "Ensuring required directories exist..."

  # List of required directories
  REQUIRED_DIRECTORIES=(
    "$CONTENT_NODE_LOG_DIR"
    "$CONTENT_NODE_DATA_DIR"
    "$CONTENT_NODE_TMP_DIR"
  )

  # Create required directories if they do not exist
  for DIR in "${REQUIRED_DIRECTORIES[@]}"; do
    if [ ! -d "$DIR" ]; then
      mkdir -p "$DIR"
      echo "Created directory: $DIR"
    fi
  done
}

# Function to perform initial health check
initial_health_check() {
  echo "Performing initial health check..."

  # Check if the service is running
  PID=$(ps -ef | grep content_node | grep -v grep | awk '{print $2}')
  if [ -z "$PID" ]; then
    echo "Content Node service is not running. Attempting to start it again..."
    start_content_node
  else
    echo "Content Node service is running (PID: $PID)."
  fi
}

# Ensure required directories exist
ensure_directories

# Start the Content Node service
start_content_node

# Perform initial health check
initial_health_check

echo "Content Node start process completed."
