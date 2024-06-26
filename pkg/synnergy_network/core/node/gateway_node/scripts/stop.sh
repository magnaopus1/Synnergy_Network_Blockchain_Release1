#!/bin/bash

# stop.sh - A comprehensive stop script for Synthron Gateway Node

# Load configuration variables
CONFIG_PATH="/etc/gateway_node/config.toml"
source $CONFIG_PATH

# Log file for stop script output
LOG_FILE="/var/log/gateway_node/stop.log"

# Function to stop a service
stop_service() {
    SERVICE_NAME=$1
    if systemctl is-active --quiet $SERVICE_NAME; then
        echo "$(date) - Stopping $SERVICE_NAME" >> $LOG_FILE
        systemctl stop $SERVICE_NAME
        if systemctl is-active --quiet $SERVICE_NAME; then
            echo "$(date) - Failed to stop $SERVICE_NAME" >> $LOG_FILE
        else
            echo "$(date) - Successfully stopped $SERVICE_NAME" >> $LOG_FILE
        fi
    else
        echo "$(date) - $SERVICE_NAME is not running" >> $LOG_FILE
    fi
}

# Function to gracefully shutdown the Gateway Node
shutdown_gateway_node() {
    echo "$(date) - Shutting down Gateway Node" >> $LOG_FILE
    pkill -f gateway_node
    if [ $? -eq 0 ]; then
        echo "$(date) - Gateway Node shut down successfully" >> $LOG_FILE
    else
        echo "$(date) - Failed to shut down Gateway Node" >> $LOG_FILE
    fi
}

# Function to perform a final security audit before shutdown
perform_security_audit() {
    echo "$(date) - Performing final security audit" >> $LOG_FILE
    AUDIT_TOOL="/usr/local/bin/security_audit_tool"
    if [ -x $AUDIT_TOOL ]; then
        $AUDIT_TOOL --config $CONFIG_PATH >> $LOG_FILE
        echo "$(date) - Final security audit completed" >> $LOG_FILE
    else
        echo "$(date) - Security audit tool not found or not executable" >> $LOG_FILE
    fi
}

# Function to backup node data
backup_node_data() {
    echo "$(date) - Backing up node data" >> $LOG_FILE
    BACKUP_DIR="/var/lib/gateway_node/backup"
    mkdir -p $BACKUP_DIR
    tar -czf $BACKUP_DIR/gateway_node_backup_$(date +%F).tar.gz /var/lib/gateway_node/data
    if [ $? -eq 0 ]; then
        echo "$(date) - Node data backup completed successfully" >> $LOG_FILE
    else
        echo "$(date) - Failed to backup node data" >> $LOG_FILE
    fi
}

# Main script execution
echo "$(date) - Starting Gateway Node stop script" >> $LOG_FILE

# Perform a final security audit before shutdown
perform_security_audit

# Backup node data
backup_node_data

# Shutdown Gateway Node
shutdown_gateway_node

# Stop related services
stop_service "firewalld"
stop_service "networking"

echo "$(date) - Gateway Node stop script completed" >> $LOG_FILE
