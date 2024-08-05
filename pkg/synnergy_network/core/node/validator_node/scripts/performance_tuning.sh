#!/bin/bash

# performance_tuning.sh - Script for optimizing the performance of the Synnergy Network Validator Node

# Variables
NODE_DIR="/var/synnergy/validator_node"
LOG_DIR="${NODE_DIR}/logs"
TUNING_LOG="${LOG_DIR}/performance_tuning.log"

# Functions

log_message() {
  echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" >> "${TUNING_LOG}"
}

# Function to optimize CPU performance
optimize_cpu() {
  log_message "Optimizing CPU performance..."
  
  # Enable CPU performance mode
  for cpu in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do
    echo performance > "$cpu"
  done

  log_message "CPU performance mode enabled."
}

# Function to optimize memory usage
optimize_memory() {
  log_message "Optimizing memory usage..."
  
  # Adjust swappiness
  sysctl vm.swappiness=10
  echo "vm.swappiness=10" >> /etc/sysctl.conf

  # Clear caches
  sync; echo 3 > /proc/sys/vm/drop_caches

  log_message "Memory usage optimized."
}

# Function to optimize disk I/O
optimize_disk_io() {
  log_message "Optimizing disk I/O..."

  # Tune I/O scheduler
  for disk in /sys/block/sd*/queue/scheduler; do
    echo noop > "$disk"
  done

  # Set readahead
  blockdev --setra 256 /dev/sda

  log_message "Disk I/O optimized."
}

# Function to optimize network settings
optimize_network() {
  log_message "Optimizing network settings..."
  
  # Increase TCP buffer sizes
  sysctl -w net.core.rmem_max=16777216
  sysctl -w net.core.wmem_max=16777216
  sysctl -w net.ipv4.tcp_rmem="4096 87380 16777216"
  sysctl -w net.ipv4.tcp_wmem="4096 65536 16777216"

  # Enable TCP window scaling
  sysctl -w net.ipv4.tcp_window_scaling=1

  # Disable TCP timestamps to reduce CPU load
  sysctl -w net.ipv4.tcp_timestamps=0

  # Apply settings
  sysctl -p

  log_message "Network settings optimized."
}

# Function to optimize system parameters
optimize_system() {
  log_message "Optimizing system parameters..."
  
  # Disable unneeded services
  systemctl stop bluetooth
  systemctl disable bluetooth

  # Set file descriptor limits
  ulimit -n 1048576

  # Enable process accounting to monitor resource usage
  systemctl enable psacct
  systemctl start psacct

  log_message "System parameters optimized."
}

# Main Script Execution

# Ensure the log directory exists
mkdir -p ${LOG_DIR}

# Perform performance tuning
log_message "Starting performance tuning..."
optimize_cpu
optimize_memory
optimize_disk_io
optimize_network
optimize_system
log_message "Performance tuning completed."

echo "Performance tuning completed. Check the log file at ${TUNING_LOG} for details."
