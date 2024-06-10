#!/bin/bash

# Constants
NODE_ID="authority_node"
LOG_FILE="/var/log/synthron/${NODE_ID}_health_check.log"
THRESHOLD_DISK_USAGE=80
THRESHOLD_CPU_LOAD=80
THRESHOLD_MEMORY_USAGE=80
THRESHOLD_NETWORK_LATENCY=100 # in ms
THRESHOLD_BLOCK_SYNC_DELAY=10 # in blocks

# Utility functions
log_message() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" >> ${LOG_FILE}
}

check_disk_usage() {
    local usage=$(df -h / | grep -v Filesystem | awk '{print $5}' | sed 's/%//g')
    if [ ${usage} -ge ${THRESHOLD_DISK_USAGE} ]; then
        log_message "Disk usage is critically high: ${usage}%"
        return 1
    fi
    log_message "Disk usage is normal: ${usage}%"
    return 0
}

check_cpu_load() {
    local load=$(top -bn1 | grep "load average:" | awk '{print $10}' | sed 's/,//g' | cut -d. -f1)
    if [ ${load} -ge ${THRESHOLD_CPU_LOAD} ]; then
        log_message "CPU load is critically high: ${load}%"
        return 1
    fi
    log_message "CPU load is normal: ${load}%"
    return 0
}

check_memory_usage() {
    local usage=$(free | grep Mem | awk '{print $3/$2 * 100.0}' | cut -d. -f1)
    if [ ${usage} -ge ${THRESHOLD_MEMORY_USAGE} ]; then
        log_message "Memory usage is critically high: ${usage}%"
        return 1
    fi
    log_message "Memory usage is normal: ${usage}%"
    return 0
}

check_network_latency() {
    local latency=$(ping -c 4 google.com | tail -1| awk '{print $4}' | cut -d '/' -f 2 | cut -d '.' -f 1)
    if [ ${latency} -ge ${THRESHOLD_NETWORK_LATENCY} ]; then
        log_message "Network latency is critically high: ${latency} ms"
        return 1
    fi
    log_message "Network latency is normal: ${latency} ms"
    return 0
}

check_block_sync() {
    local local_block=$(curl -s http://localhost:8545 | jq .result.currentBlock)
    local network_block=$(curl -s https://api.synthron_blockchain.com/status | jq .result.currentBlock)
    local sync_delay=$((network_block - local_block))
    if [ ${sync_delay} -ge ${THRESHOLD_BLOCK_SYNC_DELAY} ]; then
        log_message "Block synchronization delay is critically high: ${sync_delay} blocks"
        return 1
    fi
    log_message "Block synchronization delay is normal: ${sync_delay} blocks"
    return 0
}

# Main health check routine
log_message "Starting health check for ${NODE_ID}"

check_disk_usage || exit 1
check_cpu_load || exit 1
check_memory_usage || exit 1
check_network_latency || exit 1
check_block_sync || exit 1

log_message "Health check completed successfully for ${NODE_ID}"
exit 0
