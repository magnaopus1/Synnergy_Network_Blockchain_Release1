#!/bin/bash

# This script stops the Pruned Full Node safely

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

# Stop services related to the Pruned Full Node
function stop_services() {
  echo "Stopping Pruned Full Node services..."

  # Example: Stopping the node process
  if pgrep -f pruned_full_node > /dev/null; then
    pkill -f pruned_full_node
    echo "Pruned Full Node process stopped."
  else
    echo "Pruned Full Node process not running."
  fi

  # Example: Stopping the health check service
  HEALTH_CHECK_SERVICE=$(get_config_value "health_check_service")
  if [ -n "$HEALTH_CHECK_SERVICE" ]; then
    systemctl stop "$HEALTH_CHECK_SERVICE"
    echo "Health check service stopped: $HEALTH_CHECK_SERVICE"
  fi

  # Example: Stopping the metrics service
  METRICS_SERVICE=$(get_config_value "metrics_service")
  if [ -n "$METRICS_SERVICE" ]; then
    systemctl stop "$METRICS_SERVICE"
    echo "Metrics service stopped: $METRICS_SERVICE"
  fi

  # Example: Additional custom services to stop
  CUSTOM_SERVICES=$(get_config_value "custom_services")
  if [ -n "$CUSTOM_SERVICES" ]; then
    IFS=',' read -ra SERVICES <<< "$CUSTOM_SERVICES"
    for SERVICE in "${SERVICES[@]}"; do
      systemctl stop "$SERVICE"
      echo "Custom service stopped: $SERVICE"
    done
  fi

  echo "All Pruned Full Node services stopped."
}

# Backup the current state before stopping
function backup_node_state() {
  BACKUP_PATH=$(get_config_value "backup_path")
  if [ -n "$BACKUP_PATH" ]; then
    TIMESTAMP=$(date +"%Y%m%d%H%M%S")
    BACKUP_FILE="$BACKUP_PATH/pruned_full_node_backup_$TIMESTAMP.tar.gz"
    tar -czf "$BACKUP_FILE" -C /var/lib/synthron pruned_full_node
    echo "Node state backed up to: $BACKUP_FILE"
  else
    echo "Backup path not configured. Skipping backup."
  fi
}

# Perform pre-stop health check
function health_check() {
  HEALTH_CHECK_ENDPOINT=$(get_config_value "health_check_endpoint")
  if [ -n "$HEALTH_CHECK_ENDPOINT" ]; then
    response=$(curl --write-out "%{http_code}" --silent --output /dev/null "$HEALTH_CHECK_ENDPOINT")
    if [ "$response" -ne 200 ]; then
      echo "Health check failed. Status code: $response"
      exit 1
    fi
    echo "Health check passed."
  else
    echo "Health check endpoint not configured. Skipping health check."
  fi
}

# Main function to stop the Pruned Full Node
function main() {
  echo "Starting the Pruned Full Node stop procedure..."

  # Perform health check before stopping
  health_check

  # Backup the node state
  backup_node_state

  # Stop the node and related services
  stop_services

  echo "Pruned Full Node stopped successfully."
}

# Run the main function
main
