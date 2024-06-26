#!/bin/bash

# start.sh - Script to start the Geospatial Node

# Load configurations from the config file
CONFIG_FILE="./config.toml"
if [ ! -f "$CONFIG_FILE" ]; then
  echo "Configuration file not found: $CONFIG_FILE"
  exit 1
fi

# Function to read configuration values from the config file
get_config_value() {
  local key=$1
  grep -E "^$key\s*=" "$CONFIG_FILE" | sed -E "s/^$key\s*=\s*\"?([^\"]*)\"?/\1/"
}

NODE_ID=$(get_config_value "node_id")
LOG_DIRECTORY=$(get_config_value "log_directory")
AUDIT_TRAIL_DIRECTORY=$(get_config_value "audit_trail_directory")
DATA_DIRECTORY=$(get_config_value "data_directory")
PID_FILE="./geospatial_node.pid"

# Validate configuration values
if [ -z "$NODE_ID" ] || [ -z "$LOG_DIRECTORY" ] || [ -z "$AUDIT_TRAIL_DIRECTORY" ] || [ -z "$DATA_DIRECTORY" ]; then
  echo "Invalid configuration values. Please check the config file."
  exit 1
fi

# Create necessary directories if they do not exist
mkdir -p "$LOG_DIRECTORY" "$AUDIT_TRAIL_DIRECTORY" "$DATA_DIRECTORY"

# Check if the node is already running
if [ -f "$PID_FILE" ]; then
  if ps -p $(cat "$PID_FILE") > /dev/null; then
    echo "Geospatial Node is already running."
    exit 1
  else
    echo "Removing stale PID file."
    rm -f "$PID_FILE"
  fi
fi

# Start the Geospatial Node
echo "$(date '+%Y-%m-%d %H:%M:%S') - Starting Geospatial Node with ID: $NODE_ID" >> "$LOG_DIRECTORY/start.log"

# Command to start the Geospatial Node (replace 'geospatial_node' with the actual command)
geospatial_node --config "$CONFIG_FILE" >> "$LOG_DIRECTORY/node.log" 2>&1 &
NODE_PID=$!

# Save the PID to the PID file
echo $NODE_PID > "$PID_FILE"

# Ensure the node has started
sleep 5
if ps -p $NODE_PID > /dev/null; then
  echo "$(date '+%Y-%m-%d %H:%M:%S') - Successfully started Geospatial Node with ID: $NODE_ID" >> "$LOG_DIRECTORY/start.log"
  echo "$(date '+%Y-%m-%d %H:%M:%S') - Geospatial Node with ID: $NODE_ID started" >> "$AUDIT_TRAIL_DIRECTORY/audit.log"
else
  echo "$(date '+%Y-%m-%d %H:%M:%S') - Failed to start Geospatial Node with ID: $NODE_ID" >> "$LOG_DIRECTORY/start.log"
  exit 1
fi

# Additional initialization steps if required
# Add any additional initialization commands here

echo "Geospatial Node with ID: $NODE_ID has been started successfully."
exit 0
