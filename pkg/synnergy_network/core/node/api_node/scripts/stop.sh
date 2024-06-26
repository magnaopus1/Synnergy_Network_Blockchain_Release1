#!/bin/bash

# stop.sh - A comprehensive stop script for Synthron API Node

# Load configuration variables
CONFIG_PATH="/etc/api_node/config.toml"
LOG_FILE="/var/log/api_node/stop.log"

# Log stop activities
log() {
    echo "$(date) - $1" >> $LOG_FILE
}

# Function to stop a service
stop_service() {
    SERVICE_NAME=$1
    if systemctl is-active --quiet $SERVICE_NAME; then
        log "Stopping $SERVICE_NAME"
        systemctl stop $SERVICE_NAME
        if systemctl is-active --quiet $SERVICE_NAME; then
            log "Failed to stop $SERVICE_NAME"
        else
            log "Successfully stopped $SERVICE_NAME"
        fi
    else
        log "$SERVICE_NAME is not running"
    fi
}

# Function to gracefully shutdown the API Node
shutdown_api_node() {
    log "Shutting down API Node"
    pkill -f api_node
    if [ $? -eq 0 ]; then
        log "API Node shut down successfully"
    else
        log "Failed to shut down API Node"
    fi
}

# Function to perform a final security audit before shutdown
perform_security_audit() {
    log "Performing final security audit"
    AUDIT_TOOL="/usr/local/bin/security_audit_tool"
    if [ -x $AUDIT_TOOL ]; then
        $AUDIT_TOOL --config $CONFIG_PATH >> $LOG_FILE
        log "Final security audit completed"
    else
        log "Security audit tool not found or not executable"
    fi
}

# Function to backup node data
backup_node_data() {
    log "Backing up node data"
    BACKUP_DIR="/var/lib/api_node/backup"
    mkdir -p $BACKUP_DIR
    tar -czf $BACKUP_DIR/api_node_backup_$(date +%F).tar.gz /var/lib/api_node/data
    if [ $? -eq 0 ]; then
        log "Node data backup completed successfully"
    else
        log "Failed to backup node data"
    fi
}

# Main script execution
log "Starting API Node stop script"

# Perform a final security audit before shutdown
perform_security_audit

# Backup node data
backup_node_data

# Shutdown API Node
shutdown_api_node

# Stop related services
stop_service "firewalld"
stop_service "networking"

log "API Node stop script completed"
