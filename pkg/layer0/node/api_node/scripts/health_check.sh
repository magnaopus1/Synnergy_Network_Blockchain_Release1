#!/bin/bash

# health_check.sh - A comprehensive health check script for Synthron API Node

# Load configuration variables
CONFIG_PATH="/etc/api_node/config.toml"
LOG_FILE="/var/log/api_node/health_check.log"

# Function to check if a service is running
check_service() {
    SERVICE_NAME=$1
    if systemctl is-active --quiet $SERVICE_NAME; then
        echo "$(date) - $SERVICE_NAME is running" >> $LOG_FILE
    else
        echo "$(date) - $SERVICE_NAME is not running. Attempting to restart..." >> $LOG_FILE
        systemctl restart $SERVICE_NAME
        if systemctl is-active --quiet $SERVICE_NAME; then
            echo "$(date) - Successfully restarted $SERVICE_NAME" >> $LOG_FILE
        else
            echo "$(date) - Failed to restart $SERVICE_NAME" >> $LOG_FILE
        fi
    fi
}

# Function to check disk space
check_disk_space() {
    THRESHOLD=90
    USAGE=$(df -h | grep '/var/lib/api_node/data' | awk '{print $5}' | sed 's/%//')
    if [ $USAGE -gt $THRESHOLD ]; then
        echo "$(date) - Disk space usage is above $THRESHOLD%. Current usage: $USAGE%" >> $LOG_FILE
    else
        echo "$(date) - Disk space usage is within limits. Current usage: $USAGE%" >> $LOG_FILE
    fi
}

# Function to check network connectivity
check_network() {
    URL=$1
    if curl -s --head $URL | head -n 1 | grep "200 OK" > /dev/null; then
        echo "$(date) - Network connectivity to $URL is up" >> $LOG_FILE
    else
        echo "$(date) - Network connectivity to $URL is down" >> $LOG_FILE
    fi
}

# Function to perform security audit
perform_security_audit() {
    AUDIT_TOOL="/usr/local/bin/security_audit_tool"
    if [ -x $AUDIT_TOOL ]; then
        $AUDIT_TOOL --config $CONFIG_PATH >> $LOG_FILE
        echo "$(date) - Security audit completed" >> $LOG_FILE
    else
        echo "$(date) - Security audit tool not found or not executable" >> $LOG_FILE
    fi
}

# Check services
check_service "api-node"

# Check disk space
check_disk_space

# Check network connectivity
check_network "https://api.externaldata.com"
check_network "https://iot.device.com"

# Perform security audit
perform_security_audit

# Check SSL certificate expiration
SSL_CERT_PATH=$(grep ssl_cert_path $CONFIG_PATH | awk -F'=' '{print $2}' | sed 's/"//g')
EXPIRATION_DATE=$(openssl x509 -enddate -noout -in $SSL_CERT_PATH | cut -d'=' -f2)
CURRENT_DATE=$(date -u +"%Y-%m-%d")
DAYS_LEFT=$(( ( $(date -ud "$EXPIRATION_DATE" +'%s') - $(date -ud "$CURRENT_DATE" +'%s') ) / 86400 ))

if [ $DAYS_LEFT -lt 30 ]; then
    echo "$(date) - SSL certificate is expiring in less than 30 days. Expiration date: $EXPIRATION_DATE" >> $LOG_FILE
else
    echo "$(date) - SSL certificate is valid. Expiration date: $EXPIRATION_DATE" >> $LOG_FILE
fi

# Log end of health check
echo "$(date) - Health check completed" >> $LOG_FILE
