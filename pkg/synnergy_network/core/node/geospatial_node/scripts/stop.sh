#!/bin/bash

# stop.sh - Script to gracefully stop the Geospatial Node

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
PID_FILE="./geospatial_node.pid"

# Validate configuration values
if [ -z "$NODE_ID" ] || [ -z "$LOG_DIRECTORY" ] || [ -z "$AUDIT_TRAIL_DIRECTORY" ]; then
  echo "Invalid configuration values. Please check the config file."
  exit 1
fi

# Check if the node is running
if [ ! -f "$PID_FILE" ]; then
  echo "Geospatial Node is not running."
  exit 1
fi

NODE_PID=$(cat "$PID_FILE")

# Log the stop action
echo "$(date '+%Y-%m-%d %H:%M:%S') - Stopping Geospatial Node with ID: $NODE_ID" >> "$LOG_DIRECTORY/stop.log"

# Gracefully stop the node
kill -SIGTERM "$NODE_PID"
if [ $? -ne 0 ]; then
  echo "$(date '+%Y-%m-%d %H:%M:%S') - Failed to stop Geospatial Node with ID: $NODE_ID" >> "$LOG_DIRECTORY/stop.log"
  exit 1
fi

# Wait for the process to terminate
wait "$NODE_PID"

# Ensure the node has stopped
if ps -p "$NODE_PID" > /dev/null; then
  echo "$(date '+%Y-%m-%d %H:%M:%S') - Forcefully stopping Geospatial Node with ID: $NODE_ID" >> "$LOG_DIRECTORY/stop.log"
  kill -SIGKILL "$NODE_PID"
fi

# Remove PID file
rm -f "$PID_FILE"

# Log the successful stop action
echo "$(date '+%Y-%m-%d %H:%M:%S') - Successfully stopped Geospatial Node with ID: $NODE_ID" >> "$LOG_DIRECTORY/stop.log"

# Record the stop action in the audit trail
echo "$(date '+%Y-%m-%d %H:%M:%S') - Geospatial Node with ID: $NODE_ID stopped" >> "$AUDIT_TRAIL_DIRECTORY/audit.log"

# Cleanup temporary files or data if necessary
# Add any cleanup commands here

echo "Geospatial Node with ID: $NODE_ID has been stopped successfully."
exit 0
