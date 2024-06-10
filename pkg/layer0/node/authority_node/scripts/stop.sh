#!/bin/bash

# Constants
NODE_ID="authority_node"
LOG_FILE="/var/log/synthron/${NODE_ID}_stop.log"
PID_FILE="/var/run/synthron/${NODE_ID}.pid"

# Utility functions
log_message() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" >> ${LOG_FILE}
}

check_root() {
    if [ "$EUID" -ne 0 ]; then 
        log_message "Please run as root"
        exit 1
    fi
}

stop_node() {
    if [ -f ${PID_FILE} ]; then
        NODE_PID=$(cat ${PID_FILE})
        if kill -0 ${NODE_PID} > /dev/null 2>&1; then
            log_message "Stopping authority node with PID ${NODE_PID}"
            kill ${NODE_PID}
            if [ $? -eq 0 ]; then
                log_message "Successfully stopped authority node"
                rm -f ${PID_FILE}
            else
                log_message "Failed to stop authority node"
                exit 1
            fi
        else
            log_message "No running process found for PID ${NODE_PID}"
            rm -f ${PID_FILE}
        fi
    else
        log_message "PID file not found. Is the node running?"
        exit 1
    fi
}

perform_cleanup() {
    log_message "Performing cleanup tasks"
    # Add any additional cleanup tasks here if necessary
    log_message "Cleanup completed"
}

backup_logs() {
    log_message "Backing up log files"
    tar -czf /var/log/synthron/${NODE_ID}_logs_$(date '+%Y-%m-%d_%H-%M-%S').tar.gz /var/log/synthron/${NODE_ID}/
    if [ $? -eq 0 ]; then
        log_message "Logs backed up successfully"
    else
        log_message "Failed to back up logs"
        exit 1
    fi
}

# Main stop routine
log_message "Starting shutdown for ${NODE_ID}"

check_root
stop_node
perform_cleanup
backup_logs

log_message "Shutdown completed for ${NODE_ID}"
exit 0
