#!/bin/bash

# Stop script for Content Node

# Load environment variables
if [ -f .env ]; then
  export $(cat .env | xargs)
fi

# Function to stop the Content Node service
stop_content_node() {
  echo "Stopping Content Node service..."
  
  # Get the process ID (PID) of the running Content Node service
  PID=$(ps -ef | grep content_node | grep -v grep | awk '{print $2}')
  
  if [ -z "$PID" ]; then
    echo "Content Node service is not running."
  else
    # Attempt to stop the service gracefully
    kill -SIGTERM $PID
    echo "Sent SIGTERM signal to Content Node service (PID: $PID)."

    # Wait for the process to terminate
    sleep 5
    
    # Check if the process has terminated
    PID=$(ps -ef | grep content_node | grep -v grep | awk '{print $2}')
    if [ -z "$PID" ]; then
      echo "Content Node service stopped successfully."
    else
      # Force stop the process if it did not terminate gracefully
      kill -SIGKILL $PID
      echo "Sent SIGKILL signal to Content Node service (PID: $PID)."
    fi
  fi
}

# Function to clean up temporary files and logs
cleanup() {
  echo "Cleaning up temporary files and logs..."
  
  # Remove temporary files
  if [ -d "$CONTENT_NODE_TMP_DIR" ]; then
    rm -rf "$CONTENT_NODE_TMP_DIR"
    echo "Removed temporary files from $CONTENT_NODE_TMP_DIR."
  fi

  # Remove logs older than 7 days
  find "$CONTENT_NODE_LOG_DIR" -type f -name "*.log" -mtime +7 -exec rm {} \;
  echo "Removed logs older than 7 days from $CONTENT_NODE_LOG_DIR."
}

# Function to back up content data
backup_content_data() {
  echo "Backing up content data..."

  # Ensure backup directory exists
  mkdir -p "$CONTENT_NODE_BACKUP_DIR"

  # Perform backup
  tar -czf "$CONTENT_NODE_BACKUP_DIR/backup_$(date +%F).tar.gz" -C "$CONTENT_NODE_DATA_DIR" .
  echo "Backup completed and saved to $CONTENT_NODE_BACKUP_DIR/backup_$(date +%F).tar.gz."
}

# Stop the Content Node service
stop_content_node

# Backup content data
backup_content_data

# Clean up temporary files and logs
cleanup

echo "Content Node stop process completed."
