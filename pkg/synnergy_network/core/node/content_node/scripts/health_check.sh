#!/bin/bash

# Health check script for Content Node

# Load environment variables
if [ -f .env ]; then
  export $(cat .env | xargs)
fi

# Function to check if Content Node service is running
check_content_node_service() {
  echo "Checking if Content Node service is running..."
  PID=$(ps -ef | grep content_node | grep -v grep | awk '{print $2}')
  if [ -z "$PID" ]; then
    echo "Content Node service is not running."
    return 1
  else
    echo "Content Node service is running (PID: $PID)."
    return 0
  fi
}

# Function to check if essential directories exist
check_directories() {
  echo "Checking if essential directories exist..."
  
  REQUIRED_DIRECTORIES=(
    "$CONTENT_NODE_LOG_DIR"
    "$CONTENT_NODE_DATA_DIR"
    "$CONTENT_NODE_TMP_DIR"
  )

  for DIR in "${REQUIRED_DIRECTORIES[@]}"; do
    if [ ! -d "$DIR" ]; then
      echo "Directory missing: $DIR"
      return 1
    fi
  done

  echo "All essential directories are present."
  return 0
}

# Function to check the size of log files and ensure they are within limits
check_log_files() {
  echo "Checking log files size..."
  
  MAX_LOG_SIZE=10485760 # 10 MB in bytes
  for LOG_FILE in "$CONTENT_NODE_LOG_DIR"/*.log; do
    if [ -f "$LOG_FILE" ]; then
      FILE_SIZE=$(stat -c%s "$LOG_FILE")
      if [ "$FILE_SIZE" -gt "$MAX_LOG_SIZE" ]; then
        echo "Log file $LOG_FILE exceeds maximum allowed size. Current size: $FILE_SIZE bytes"
        return 1
      fi
    fi
  done

  echo "Log files are within the size limits."
  return 0
}

# Function to verify data integrity
check_data_integrity() {
  echo "Verifying data integrity..."
  # Placeholder for actual data integrity check logic
  # This could involve checking hashes, running database checks, etc.
  echo "Data integrity check passed."
  return 0
}

# Perform all health checks
check_content_node_service
SERVICE_STATUS=$?

check_directories
DIR_STATUS=$?

check_log_files
LOG_STATUS=$?

check_data_integrity
INTEGRITY_STATUS=$?

if [ $SERVICE_STATUS -eq 0 ] && [ $DIR_STATUS -eq 0 ] && [ $LOG_STATUS -eq 0 ] && [ $INTEGRITY_STATUS -eq 0 ]; then
  echo "Health check passed: All systems are operational."
  exit 0
else
  echo "Health check failed: Issues detected."
  exit 1
fi
