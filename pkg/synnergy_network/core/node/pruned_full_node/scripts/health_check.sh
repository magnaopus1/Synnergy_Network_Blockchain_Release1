#!/bin/bash

# This script performs a health check on the Pruned Full Node

# Load the configuration file
CONFIG_FILE="/etc/synthron/pruned_full_node/config.toml"
if [ ! -f "$CONFIG_FILE" ]; then
  echo "Configuration file not found: $CONFIG_FILE"
  exit 1
fi

# Function to read values from the config file
function get_config_value() {
  local key=$1
  grep "^$key" "$CONFIG_FILE" | sed -E 's/.* = "(.*)"/\1/'
}

# Check if the node process is running
function check_node_process() {
  NODE_PROCESS=$(get_config_value "node_process_name")
  if pgrep -x "$NODE_PROCESS" > /dev/null; then
    echo "Node process is running: $NODE_PROCESS"
  else
    echo "Node process is not running: $NODE_PROCESS"
    exit 1
  fi
}

# Check node synchronization status
function check_sync_status() {
  SYNC_ENDPOINT=$(get_config_value "sync_status_endpoint")
  if [ -n "$SYNC_ENDPOINT" ]; then
    response=$(curl --silent --max-time 5 "$SYNC_ENDPOINT")
    if [[ "$response" == *"synced"* ]]; then
      echo "Node is synchronized with the blockchain."
    else
      echo "Node is not synchronized with the blockchain."
      exit 1
    fi
  else
    echo "Sync status endpoint not configured. Skipping sync status check."
  fi
}

# Check disk space usage
function check_disk_space() {
  THRESHOLD=$(get_config_value "disk_space_threshold")
  if [ -z "$THRESHOLD" ]; then
    THRESHOLD=90
  fi
  USAGE=$(df -h | grep '/$' | awk '{print $5}' | sed 's/%//')
  if [ "$USAGE" -lt "$THRESHOLD" ]; then
    echo "Disk space usage is within limits: $USAGE% used."
  else
    echo "Disk space usage is above threshold: $USAGE% used. Threshold is $THRESHOLD%."
    exit 1
  fi
}

# Check memory usage
function check_memory_usage() {
  THRESHOLD=$(get_config_value "memory_usage_threshold")
  if [ -z "$THRESHOLD" ]; then
    THRESHOLD=80
  fi
  USAGE=$(free | grep Mem | awk '{print $3/$2 * 100.0}')
  if (( $(echo "$USAGE < $THRESHOLD" | bc -l) )); then
    echo "Memory usage is within limits: $USAGE% used."
  else
    echo "Memory usage is above threshold: $USAGE% used. Threshold is $THRESHOLD%."
    exit 1
  fi
}

# Check network connectivity
function check_network_connectivity() {
  PING_ADDRESS=$(get_config_value "ping_address")
  if [ -z "$PING_ADDRESS" ]; then
    PING_ADDRESS="8.8.8.8"
  fi
  if ping -c 1 "$PING_ADDRESS" &> /dev/null; then
    echo "Network connectivity is active."
  else
    echo "Network connectivity is down."
    exit 1
  fi
}

# Main function to perform health checks
function main() {
  echo "Starting Pruned Full Node health check..."

  # Check if the node process is running
  check_node_process

  # Check node synchronization status
  check_sync_status

  # Check disk space usage
  check_disk_space

  # Check memory usage
  check_memory_usage

  # Check network connectivity
  check_network_connectivity

  echo "Pruned Full Node health check completed successfully."
}

# Run the main function
main
