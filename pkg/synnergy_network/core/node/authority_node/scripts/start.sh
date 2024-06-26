#!/bin/bash

# Constants
NODE_ID="authority_node"
LOG_FILE="/var/log/synthron/${NODE_ID}_start.log"
CONFIG_FILE="/etc/synthron/${NODE_ID}/config.toml"
DATA_DIR="/var/lib/synthron/${NODE_ID}/data"
LOG_DIR="/var/log/synthron/${NODE_ID}/logs"

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

initialize_directories() {
    mkdir -p ${DATA_DIR}
    mkdir -p ${LOG_DIR}
    log_message "Initialized data and log directories"
}

load_configuration() {
    if [ ! -f ${CONFIG_FILE} ]; then
        log_message "Configuration file not found: ${CONFIG_FILE}"
        exit 1
    fi
    log_message "Loaded configuration from ${CONFIG_FILE}"
}

start_node() {
    log_message "Starting authority node"
    nohup /usr/local/bin/synthron_node --config ${CONFIG_FILE} --datadir ${DATA_DIR} > ${LOG_DIR}/node.log 2>&1 &
    NODE_PID=$!
    log_message "Authority node started with PID ${NODE_PID}"
    echo ${NODE_PID} > /var/run/synthron/${NODE_ID}.pid
}

setup_firewall() {
    log_message "Setting up firewall rules"
    ufw allow 30303/tcp comment 'synthron node port'
    ufw allow 30303/udp comment 'synthron node port'
    ufw reload
    log_message "Firewall rules configured"
}

enable_automatic_updates() {
    log_message "Enabling automatic security updates"
    apt-get install -y unattended-upgrades
    dpkg-reconfigure -plow unattended-upgrades
    log_message "Automatic security updates enabled"
}

configure_logging() {
    log_message "Configuring log rotation"
    cat <<EOF > /etc/logrotate.d/synthron
${LOG_DIR}/node.log {
    daily
    rotate 14
    compress
    delaycompress
    missingok
    notifempty
    create 640 root adm
}
EOF
    log_message "Log rotation configured"
}

# Main startup routine
log_message "Starting initialization for ${NODE_ID}"

check_root
initialize_directories
load_configuration
start_node
setup_firewall
enable_automatic_updates
configure_logging

log_message "Initialization completed for ${NODE_ID}"
exit 0
