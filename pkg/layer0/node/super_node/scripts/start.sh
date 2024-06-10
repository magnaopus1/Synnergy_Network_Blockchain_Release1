#!/bin/bash

# start.sh - Script to start the Super Node

# Function to print the script usage
usage() {
  echo "Usage: $0 [-h|--help]"
  echo "Options:"
  echo "  -h, --help    Show this help message"
  exit 1
}

# Parse command-line arguments
while [[ "$1" != "" ]]; do
  case $1 in
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

# Function to check if the node is already running
check_running() {
  local pid_file="super_node.pid"
  if [[ -f "$pid_file" ]]; then
    local pid=$(cat $pid_file)
    if kill -0 $pid 2>/dev/null; then
      echo "Super Node is already running with PID $pid."
      exit 1
    else
      echo "Stale PID file found. Removing..."
      rm -f $pid_file
    fi
  fi
}

# Function to start the node
start_node() {
  echo "Starting Super Node..."

  # Define the command to start the Super Node
  local start_command="nohup ./super_node > logs/super_node.log 2>&1 &"
  
  # Execute the start command
  eval $start_command
  
  # Capture the PID of the started process
  local pid=$!
  echo $pid > super_node.pid
  
  echo "Super Node started with PID $pid."
}

# Function to ensure necessary directories exist
prepare_directories() {
  local dirs=("logs" "data")
  for dir in "${dirs[@]}"; do
    if [[ ! -d $dir ]]; then
      echo "Creating directory $dir..."
      mkdir -p $dir
    fi
  done
}

# Check if the node is already running
check_running

# Prepare necessary directories
prepare_directories

# Start the node
start_node

# Function to check the status of the node
check_status() {
  local pid_file="super_node.pid"
  if [[ -f "$pid_file" ]]; then
    local pid=$(cat $pid_file)
    if kill -0 $pid 2>/dev/null; then
      echo "Super Node is running with PID $pid."
    else
      echo "Error: Super Node is not running. Check logs for details."
      exit 1
    fi
  else
    echo "Error: PID file $pid_file not found. Super Node may not have started correctly."
    exit 1
  fi
}

# Check status to confirm the node has started
check_status

echo "Super Node has been started successfully."
