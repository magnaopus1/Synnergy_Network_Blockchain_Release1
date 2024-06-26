#!/bin/bash

# Define the log file
LOGFILE="/var/log/bank_institutional_node_healthcheck.log"

# Function to log to syslog and stdout
log() {
    echo "$(date +'%Y-%m-%d %H:%M:%S') - $1"
    echo "$(date +'%Y-%m-%d %H:%M:%S') - $1" >> $LOGFILE
}

# Checking server CPU load
check_cpu_load() {
    log "Checking CPU load..."
    CPU_LOAD=$(top -bn1 | grep "load average:" | awk '{print $10}' | cut -d ',' -f1)
    if (( $(echo "$CPU_LOAD > 2.5" | bc -l) )); then
        log "High CPU load detected: $CPU_LOAD"
    else
        log "CPU load is normal: $CPU_LOAD"
    fi
}

# Checking available RAM
check_ram() {
    log "Checking available RAM..."
    AVAILABLE_RAM=$(free -m | awk '/^Mem:/{print $7}')
    if (( $AVAILABLE_RAM < 2048 )); then
        log "Low RAM available: $AVAILABLE_RAM MB"
    else
        log "Sufficient RAM available: $AVAILABLE_RAM MB"
    fi
}

# Checking disk space
check_disk() {
    log "Checking disk space..."
    DISK_USAGE=$(df / | grep / | awk '{ print $5 }' | sed 's/%//g')
    if [ $DISK_USAGE -gt 85 ]; then
        log "Disk space usage is high: $DISK_USAGE%"
    else
        log "Disk space usage is normal: $DISK_USAGE%"
    fi
}

# Checking network connectivity
check_network() {
    log "Checking network connectivity..."
    if ! ping -c 1 -W 2 google.com > /dev/null 2>&1; then
        log "Network connectivity issue detected!"
    else
        log "Network connectivity is stable."
    fi
}

# Check compliance and security module processes
check_processes() {
    log "Checking critical processes..."
    # Example: Check if the compliance manager process is running
    if pgrep -x "compliance_manager" > /dev/null; then
        log "Compliance Manager process is running."
    else
        log "Compliance Manager process is not running!"
    fi
}

# Main function to run checks
main() {
    log "Starting health check..."
    check_cpu_load
    check_ram
    check_disk
    check_network
    check_processes
    log "Health check completed."
}

main
