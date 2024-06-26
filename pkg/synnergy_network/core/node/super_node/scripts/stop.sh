#!/bin/bash

# stop.sh - Script to gracefully stop the Super Node

# Function to print the script usage
usage() {
  echo "Usage: $0 [-f|--force] [-h|--help]"
  echo "Options:"
  echo "  -f, --force    Force stop the node"
  echo "  -h, --help     Show this help message"
  exit 1
}

# Parse command-line arguments
FORCE_STOP=0
while [[ "$1" != "" ]]; do
  case $1 in
    -f | --force ) FORCE_STOP=1
                   ;;
    -h | --help )  usage
                   ;;
    * )            usage
                   ;;
  esac
  shift
done

# Load node configuration
CONFIG_FILE="config.toml"
if [[ ! -f "$CONFIG_FILE" ]]; then
  echo "Error: Configuration file $CONFIG_FILE not found."
  exit 1
fi

# Source configuration
source $CONFIG_FILE

# Function to stop the node
stop_node() {
  local pid_file="super_node.pid"
  if [[ ! -f "$pid_file" ]]; then
    echo "Error: PID file $pid_file not found. Is the node running?"
    exit 1
  fi

  local pid=$(cat $pid_file)
  if [[ -z "$pid" ]]; then
    echo "Error: PID is empty. Unable to stop the node."
    exit 1
  fi

  echo "Stopping Super Node with PID $pid..."
  if [[ $FORCE_STOP -eq 1 ]]; then
    kill -9 $pid
    echo "Super Node forcefully stopped."
  else
    kill -SIGTERM $pid
    echo "Super Node gracefully stopping..."

    # Wait for the process to terminate
    local wait_time=0
    local max_wait_time=30 # seconds
    while kill -0 $pid 2>/dev/null; do
      sleep 1
      wait_time=$((wait_time + 1))
      if [[ $wait_time -ge $max_wait_time ]]; then
        echo "Error: Super Node did not stop in time. Force stopping..."
        kill -9 $pid
        break
      fi
    done
    echo "Super Node stopped."
  fi

  # Remove PID file
  rm -f $pid_file
}

# Function to perform cleanup tasks
cleanup() {
  echo "Performing cleanup tasks..."
  # Add any additional cleanup tasks here
  echo "Cleanup complete."
}

# Function to check node status
check_status() {
  local pid_file="super_node.pid"
  if [[ -f "$pid_file" ]]; then
    local pid=$(cat $pid_file)
    if kill -0 $pid 2>/dev/null; then
      echo "Super Node is still running with PID $pid."
      exit 1
    else
      echo "Super Node is not running."
    fi
  else
    echo "Super Node is not running."
  fi
}

# Stop the node
stop_node

# Perform cleanup
cleanup

# Check status to confirm the node has stopped
check_status

echo "Super Node has been stopped successfully."
