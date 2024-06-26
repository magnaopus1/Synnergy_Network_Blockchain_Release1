#!/bin/bash

# start.sh - A comprehensive startup script for Synthron Gateway Node

# Load configuration variables
CONFIG_PATH="/etc/gateway_node/config.toml"
source $CONFIG_PATH

# Log file for startup output
LOG_FILE="/var/log/gateway_node/startup.log"

# Function to check if a service is running
check_service() {
    SERVICE_NAME=$1
    if systemctl is-active --quiet $SERVICE_NAME; then
        echo "$(date) - $SERVICE_NAME is running" >> $LOG_FILE
    else
        echo "$(date) - $SERVICE_NAME is not running. Attempting to start..." >> $LOG_FILE
        systemctl start $SERVICE_NAME
        if systemctl is-active --quiet $SERVICE_NAME; then
            echo "$(date) - Successfully started $SERVICE_NAME" >> $LOG_FILE
        else
            echo "$(date) - Failed to start $SERVICE_NAME" >> $LOG_FILE
        fi
    fi
}

# Function to initialize the node environment
initialize_node() {
    echo "$(date) - Initializing Gateway Node environment" >> $LOG_FILE
    mkdir -p /var/lib/gateway_node/data
    mkdir -p /var/log/gateway_node
    chown -R gateway:gateway /var/lib/gateway_node /var/log/gateway_node
}

# Function to start the Gateway Node
start_gateway_node() {
    echo "$(date) - Starting Gateway Node" >> $LOG_FILE
    su - gateway -c "gateway_node -config $CONFIG_PATH &" >> $LOG_FILE 2>&1
    if [ $? -eq 0 ]; then
        echo "$(date) - Gateway Node started successfully" >> $LOG_FILE
    else
        echo "$(date) - Failed to start Gateway Node" >> $LOG_FILE
    fi
}

# Function to check SSL certificate expiration
check_ssl_certificate() {
    echo "$(date) - Checking SSL certificate expiration" >> $LOG_FILE
    SSL_CERT_PATH=$(grep ssl_cert_path $CONFIG_PATH | awk -F'=' '{print $2}' | sed 's/"//g')
    EXPIRATION_DATE=$(openssl x509 -enddate -noout -in $SSL_CERT_PATH | cut -d'=' -f2)
    CURRENT_DATE=$(date -u +"%Y-%m-%d")
    DAYS_LEFT=$(( ( $(date -ud "$EXPIRATION_DATE" +'%s') - $(date -ud "$CURRENT_DATE" +'%s') ) / 86400 ))

    if [ $DAYS_LEFT -lt 30 ]; then
        echo "$(date) - SSL certificate is expiring in less than 30 days. Expiration date: $EXPIRATION_DATE" >> $LOG_FILE
    else
        echo "$(date) - SSL certificate is valid. Expiration date: $EXPIRATION_DATE" >> $LOG_FILE
    fi
}

# Function to perform a security audit
perform_security_audit() {
    echo "$(date) - Performing security audit" >> $LOG_FILE
    AUDIT_TOOL="/usr/local/bin/security_audit_tool"
    if [ -x $AUDIT_TOOL ]; then
        $AUDIT_TOOL --config $CONFIG_PATH >> $LOG_FILE
        echo "$(date) - Security audit completed" >> $LOG_FILE
    else
        echo "$(date) - Security audit tool not found or not executable" >> $LOG_FILE
    fi
}

# Main script execution
echo "$(date) - Starting Gateway Node initialization script" >> $LOG_FILE

# Initialize node environment
initialize_node

# Check required services
check_service "networking"
check_service "firewalld"

# Start Gateway Node
start_gateway_node

# Check SSL certificate expiration
check_ssl_certificate

# Perform security audit
perform_security_audit

echo "$(date) - Gateway Node initialization script completed" >> $LOG_FILE
