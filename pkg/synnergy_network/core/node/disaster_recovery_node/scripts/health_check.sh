#!/bin/bash

# Script to perform health checks on the Disaster Recovery Node

# Load environment variables
if [ -f .env ]; then
  export $(cat .env | xargs)
fi

# Function to check if the node process is running
check_node_process() {
  echo "Checking Disaster Recovery Node process..."

  NODE_PID_FILE="${DATA_DIR}/node.pid"
  if [ -f "$NODE_PID_FILE" ]; then
    NODE_PID=$(cat "$NODE_PID_FILE")
    if kill -0 "$NODE_PID" 2>/dev/null; then
      echo "Node is running with PID: $NODE_PID"
    else
      echo "Node process not found. PID file exists but no process is running."
      return 1
    fi
  else
    echo "Node PID file not found. Node may not be running."
    return 1
  fi
}

# Function to check if the backup process is running
check_backup_process() {
  echo "Checking backup process..."

  BACKUP_PID_FILE="${DATA_DIR}/backup.pid"
  if [ -f "$BACKUP_PID_FILE" ]; then
    BACKUP_PID=$(cat "$BACKUP_PID_FILE")
    if kill -0 "$BACKUP_PID" 2>/dev/null; then
      echo "Backup process is running with PID: $BACKUP_PID"
    else
      echo "Backup process not found. PID file exists but no process is running."
      return 1
    fi
  else
    echo "Backup PID file not found. Backup process may not be running."
    return 1
  fi
}

# Function to check if the node can communicate with the network
check_network_communication() {
  echo "Checking network communication..."

  NODE_HOST="127.0.0.1"
  NODE_PORT=${NODE_PORT:-8080}

  if nc -z "$NODE_HOST" "$NODE_PORT"; then
    echo "Node is successfully communicating on port $NODE_PORT."
  else
    echo "Node is not responding on port $NODE_PORT."
    return 1
  fi
}

# Function to check if backups are up-to-date
check_backup_freshness() {
  echo "Checking backup freshness..."

  BACKUP_DIR="${DATA_DIR}/backups"
  LATEST_BACKUP=$(find "$BACKUP_DIR" -type f -name "*.backup" -printf "%T@ %p\n" | sort -n | tail -1 | cut -d' ' -f2-)

  if [ -n "$LATEST_BACKUP" ]; then
    BACKUP_TIME=$(stat -c %Y "$LATEST_BACKUP")
    CURRENT_TIME=$(date +%s)
    TIME_DIFF=$((CURRENT_TIME - BACKUP_TIME))

    if [ "$TIME_DIFF" -le 86400 ]; then
      echo "Latest backup is up-to-date. Created $((TIME_DIFF / 60)) minutes ago."
    else
      echo "Latest backup is stale. Created $((TIME_DIFF / 86400)) days ago."
      return 1
    fi
  else
    echo "No backups found in the backup directory."
    return 1
  fi
}

# Main script execution
echo "Starting health check for Disaster Recovery Node..."

check_node_process || exit 1
check_backup_process || exit 1
check_network_communication || exit 1
check_backup_freshness || exit 1

echo "Health check completed successfully. All systems are operational."
