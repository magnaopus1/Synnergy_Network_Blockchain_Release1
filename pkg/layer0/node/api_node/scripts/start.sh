#!/bin/bash

# start.sh - A comprehensive startup script for Synthron API Node

# Load configuration variables
CONFIG_PATH="/etc/api_node/config.toml"
LOG_FILE="/var/log/api_node/startup.log"

# Log startup activities
log() {
    echo "$(date) - $1" >> $LOG_FILE
}

# Function to check if a service is running
check_service() {
    SERVICE_NAME=$1
    if systemctl is-active --quiet $SERVICE_NAME; then
        log "$SERVICE_NAME is running"
    else
        log "$SERVICE_NAME is not running. Attempting to start..."
        systemctl start $SERVICE_NAME
        if systemctl is-active --quiet $SERVICE_NAME; then
            log "Successfully started $SERVICE_NAME"
        else
            log "Failed to start $SERVICE_NAME"
        fi
    fi
}

# Function to initialize the node environment
initialize_node() {
    log "Initializing API Node environment"
    mkdir -p /var/lib/api_node/data
    mkdir -p /var/log/api_node
    chown -R api:api /var/lib/api_node /var/log/api_node
}

# Function to start the API Node
start_api_node() {
    log "Starting API Node"
    su - api -c "api_node -config $CONFIG_PATH &" >> $LOG_FILE 2>&1
    if [ $? -eq 0 ]; then
        log "API Node started successfully"
    else
        log "Failed to start API Node"
    fi
}

# Function to check SSL certificate expiration
check_ssl_certificate() {
    log "Checking SSL certificate expiration"
    SSL_CERT_PATH=$(grep ssl_cert_path $CONFIG_PATH | awk -F'=' '{print $2}' | sed 's/"//g')
    EXPIRATION_DATE=$(openssl x509 -enddate -noout -in $SSL_CERT_PATH | cut -d'=' -f2)
    CURRENT_DATE=$(date -u +"%Y-%m-%d")
    DAYS_LEFT=$(( ( $(date -ud "$EXPIRATION_DATE" +'%s') - $(date -ud "$CURRENT_DATE" +'%s') ) / 86400 ))

    if [ $DAYS_LEFT -lt 30 ]; then
        log "SSL certificate is expiring in less than 30 days. Expiration date: $EXPIRATION_DATE"
    else
        log "SSL certificate is valid. Expiration date: $EXPIRATION_DATE"
    fi
}

# Function to perform a security audit
perform_security_audit() {
    log "Performing security audit"
    AUDIT_TOOL="/usr/local/bin/security_audit_tool"
    if [ -x $AUDIT_TOOL ]; then
        $AUDIT_TOOL --config $CONFIG_PATH >> $LOG_FILE
        log "Security audit completed"
    else
        log "Security audit tool not found or not executable"
    fi
}

# Main script execution
log "Starting API Node initialization script"

# Initialize node environment
initialize_node

# Check required services
check_service "networking"
check_service "firewalld"

# Start API Node
start_api_node

# Check SSL certificate expiration
check_ssl_certificate

# Perform security audit
perform_security_audit

log "API Node initialization script completed"
