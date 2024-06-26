#!/bin/bash

# health_check.sh - Script to perform health checks on the Geospatial Node

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
DATA_DIRECTORY=$(get_config_value "data_directory")
PID_FILE="./geospatial_node.pid"

# Validate configuration values
if [ -z "$NODE_ID" ] || [ -z "$LOG_DIRECTORY" ] || [ -z "$DATA_DIRECTORY" ]; then
  echo "Invalid configuration values. Please check the config file."
  exit 1
fi

# Function to check if a service is running
check_service() {
  local service_name=$1
  if systemctl is-active --quiet "$service_name"; then
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $service_name is running." >> "$LOG_DIRECTORY/health_check.log"
  else
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $service_name is not running." >> "$LOG_DIRECTORY/health_check.log"
  fi
}

# Check if the Geospatial Node is running
if [ -f "$PID_FILE" ]; then
  if ps -p $(cat "$PID_FILE") > /dev/null; then
    echo "$(date '+%Y-%m-%d %H:%M:%S') - Geospatial Node with ID: $NODE_ID is running." >> "$LOG_DIRECTORY/health_check.log"
  else
    echo "$(date '+%Y-%m-%d %H:%M:%S') - Geospatial Node with ID: $NODE_ID is not running." >> "$LOG_DIRECTORY/health_check.log"
  fi
else
  echo "$(date '+%Y-%m-%d %H:%M:%S') - PID file not found. Geospatial Node might not be running." >> "$LOG_DIRECTORY/health_check.log"
fi

# Check system resource usage
echo "$(date '+%Y-%m-%d %H:%M:%S') - Checking system resource usage..." >> "$LOG_DIRECTORY/health_check.log"
echo "CPU Usage: $(top -bn1 | grep "Cpu(s)" | sed "s/.*, *\([0-9.]*\)%* id.*/\1/")%" >> "$LOG_DIRECTORY/health_check.log"
echo "Memory Usage: $(free -m | awk 'NR==2{printf "%.2f%%", $3*100/$2 }')" >> "$LOG_DIRECTORY/health_check.log"
echo "Disk Usage: $(df -h | grep "$DATA_DIRECTORY" | awk '{print $5}')" >> "$LOG_DIRECTORY/health_check.log"

# Check network connectivity
echo "$(date '+%Y-%m-%d %H:%M:%S') - Checking network connectivity..." >> "$LOG_DIRECTORY/health_check.log"
if ping -c 1 google.com &> /dev/null; then
  echo "Network is up." >> "$LOG_DIRECTORY/health_check.log"
else
  echo "Network is down." >> "$LOG_DIRECTORY/health_check.log"
fi

# Check key services (example: GIS service, Database service)
check_service "gis_service"
check_service "database_service"

# Analyze logs for errors or warnings
echo "$(date '+%Y-%m-%d %H:%M:%S') - Analyzing logs for errors or warnings..." >> "$LOG_DIRECTORY/health_check.log"
grep -E "ERROR|WARNING" "$LOG_DIRECTORY/node.log" >> "$LOG_DIRECTORY/health_check.log" || echo "No errors or warnings found in logs." >> "$LOG_DIRECTORY/health_check.log"

# Print summary
echo "Health check completed. See $LOG_DIRECTORY/health_check.log for details."
