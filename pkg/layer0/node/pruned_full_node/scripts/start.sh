#!/bin/bash

# This script starts the Pruned Full Node safely

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

# Start services related to the Pruned Full Node
function start_services() {
  echo "Starting Pruned Full Node services..."

  # Example: Starting the node process
  nohup pruned_full_node --config "$CONFIG_FILE" > /var/log/synthron/pruned_full_node.log 2>&1 &
  echo "Pruned Full Node process started."

  # Example: Starting the health check service
  HEALTH_CHECK_SERVICE=$(get_config_value "health_check_service")
  if [ -n "$HEALTH_CHECK_SERVICE" ]; then
    systemctl start "$HEALTH_CHECK_SERVICE"
    echo "Health check service started: $HEALTH_CHECK_SERVICE"
  fi

  # Example: Starting the metrics service
  METRICS_SERVICE=$(get_config_value "metrics_service")
  if [ -n "$METRICS_SERVICE" ]; then
    systemctl start "$METRICS_SERVICE"
    echo "Metrics service started: $METRICS_SERVICE"
  fi

  # Example: Additional custom services to start
  CUSTOM_SERVICES=$(get_config_value "custom_services")
  if [ -n "$CUSTOM_SERVICES" ]; then
    IFS=',' read -ra SERVICES <<< "$CUSTOM_SERVICES"
    for SERVICE in "${SERVICES[@]}"; do
      systemctl start "$SERVICE"
      echo "Custom service started: $SERVICE"
    done
  fi

  echo "All Pruned Full Node services started."
}

# Sync the node with the blockchain
function sync_blockchain() {
  echo "Syncing the node with the blockchain..."
  pruned_full_node --config "$CONFIG_FILE" --sync
  echo "Node synced with the blockchain."
}

# Perform post-start health check
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

# Main function to start the Pruned Full Node
function main() {
  echo "Starting the Pruned Full Node start procedure..."

  # Sync the node with the blockchain
  sync_blockchain

  # Start the node and related services
  start_services

  # Perform health check after starting
  health_check

  echo "Pruned Full Node started successfully."
}

# Run the main function
main
