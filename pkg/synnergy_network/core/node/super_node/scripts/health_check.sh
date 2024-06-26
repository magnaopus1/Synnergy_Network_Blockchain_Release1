#!/bin/bash

# health_check.sh - Script to perform a health check on the Super Node

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

# Configuration
CONFIG_FILE="config.toml"
PID_FILE="super_node.pid"
LOG_FILE="logs/super_node.log"

# Function to check if the node is running
check_running() {
  if [[ -f "$PID_FILE" ]]; then
    local pid=$(cat $PID_FILE)
    if kill -0 $pid 2>/dev/null; then
      echo "Super Node is running with PID $pid."
    else
      echo "Error: Super Node is not running. PID $pid found but no process exists."
      exit 1
    fi
  else
    echo "Error: PID file $PID_FILE not found. Super Node may not be running."
    exit 1
  fi
}

# Function to check log file for errors
check_logs() {
  if [[ -f "$LOG_FILE" ]]; then
    local error_count=$(grep -i "error" "$LOG_FILE" | wc -l)
    if [[ $error_count -gt 0 ]]; then
      echo "Warning: Found $error_count error(s) in the log file."
    else
      echo "Log file is clean. No errors found."
    fi
  else
    echo "Error: Log file $LOG_FILE not found."
    exit 1
  fi
}

# Function to check disk space
check_disk_space() {
  local data_dir="data"
  if [[ -d "$data_dir" ]]; then
    local space_left=$(df -h "$data_dir" | tail -1 | awk '{print $4}')
    echo "Disk space available in $data_dir: $space_left"
  else
    echo "Error: Data directory $data_dir not found."
    exit 1
  fi
}

# Function to check network connectivity
check_network() {
  local host="8.8.8.8"
  if ping -c 1 $host &> /dev/null; then
    echo "Network connectivity is up."
  else
    echo "Error: Network connectivity is down."
    exit 1
  fi
}

# Function to check CPU and memory usage
check_system_resources() {
  local cpu_usage=$(top -b -n1 | grep "Cpu(s)" | awk '{print $2 + $4}')
  local mem_usage=$(free -m | awk '/Mem:/ { printf("%.2f"), $3/$2*100 }')
  echo "CPU usage: $cpu_usage%"
  echo "Memory usage: $mem_usage%"
}

# Perform health checks
check_running
check_logs
check_disk_space
check_network
check_system_resources

echo "Super Node health check completed successfully."
