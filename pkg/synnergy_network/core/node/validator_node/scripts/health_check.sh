#!/bin/bash

# health_check.sh - Script for performing health checks on the Synnergy Network Validator Node

# Variables
NODE_DIR="/var/synnergy/validator_node"
LOG_DIR="${NODE_DIR}/logs"
HEALTH_LOG="${LOG_DIR}/health_check.log"
CPU_THRESHOLD=85
MEMORY_THRESHOLD=90
DISK_THRESHOLD=80

# Functions

log_message() {
  echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" >> "${HEALTH_LOG}"
}

check_cpu_usage() {
  local cpu_usage
  cpu_usage=$(top -bn1 | grep "Cpu(s)" | sed "s/.*, *\([0-9.]*\)%* id.*/\1/" | awk '{print 100 - $1}')
  log_message "CPU Usage: ${cpu_usage}%"
  if (( $(echo "${cpu_usage} > ${CPU_THRESHOLD}" | bc -l) )); then
    log_message "Warning: CPU usage exceeds ${CPU_THRESHOLD}%"
  fi
}

check_memory_usage() {
  local memory_usage
  memory_usage=$(free | grep Mem | awk '{print $3/$2 * 100.0}')
  log_message "Memory Usage: ${memory_usage}%"
  if (( $(echo "${memory_usage} > ${MEMORY_THRESHOLD}" | bc -l) )); then
    log_message "Warning: Memory usage exceeds ${MEMORY_THRESHOLD}%"
  fi
}

check_disk_usage() {
  local disk_usage
  disk_usage=$(df -h | grep -E '^/dev/root' | awk '{ print $5 }' | sed 's/%//g')
  log_message "Disk Usage: ${disk_usage}%"
  if ((disk_usage > DISK_THRESHOLD)); then
    log_message "Warning: Disk usage exceeds ${DISK_THRESHOLD}%"
  fi
}

check_network_latency() {
  local latency
  latency=$(ping -c 4 google.com | tail -1 | awk -F '/' '{print $5}')
  log_message "Network Latency: ${latency} ms"
}

check_transactions_validated() {
  local transactions_validated
  transactions_validated=$(grep -c 'Transaction Validated' ${LOG_DIR}/validator_node.log)
  log_message "Transactions Validated: ${transactions_validated}"
}

check_blocks_created() {
  local blocks_created
  blocks_created=$(grep -c 'Block Created' ${LOG_DIR}/validator_node.log)
  log_message "Blocks Created: ${blocks_created}"
}

check_system_health() {
  log_message "Starting system health check..."
  check_cpu_usage
  check_memory_usage
  check_disk_usage
  check_network_latency
  check_transactions_validated
  check_blocks_created
  log_message "System health check completed."
}

# Main Script Execution

# Ensure the log directory exists
mkdir -p ${LOG_DIR}

# Perform health checks
check_system_health

echo "Health check completed. Check the log file at ${HEALTH_LOG} for details."
