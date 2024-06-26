#!/bin/bash

# Synthron Master Node Start Script
# This script initializes and starts the Synthron Master Node safely and efficiently.

# Function to print messages
log_message() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $1"
}

# Function to ensure the log directory exists
ensure_log_directory() {
    LOG_DIR="/var/log/synthron"
    if [ ! -d "$LOG_DIR" ]; then
        mkdir -p "$LOG_DIR"
        log_message "Created log directory: $LOG_DIR"
    fi
}

# Function to ensure the data directory exists
ensure_data_directory() {
    DATA_DIR="/var/lib/synthron/data"
    if [ ! -d "$DATA_DIR" ]; then
        mkdir -p "$DATA_DIR"
        log_message "Created data directory: $DATA_DIR"
    fi
}

# Function to check if necessary software is installed
check_software() {
    REQUIRED_SOFTWARE=("synthron_master_node" "curl" "jq")
    for software in "${REQUIRED_SOFTWARE[@]}"; do
        if ! command -v $software &> /dev/null; then
            log_message "Error: $software is not installed."
            exit 1
        fi
    done
    log_message "All required software is installed."
}

# Function to check network connectivity
check_network() {
    log_message "Checking network connectivity..."
    if ! ping -c 1 google.com &> /dev/null; then
        log_message "Error: No network connectivity. Please check your internet connection."
        exit 1
    fi
    log_message "Network connectivity is OK."
}

# Function to load configuration
load_configuration() {
    CONFIG_FILE="/etc/synthron/config.toml"
    if [ ! -f "$CONFIG_FILE" ]; then
        log_message "Error: Configuration file not found at $CONFIG_FILE."
        exit 1
    fi
    log_message "Loaded configuration file from $CONFIG_FILE."
}

# Function to start the Master Node
start_master_node() {
    log_message "Starting Synthron Master Node..."

    # Execute the master node start command
    synthron_master_node --config /etc/synthron/config.toml --data-dir /var/lib/synthron/data &

    # Save the process ID
    echo $! > /var/run/synthron_master_node.pid
    log_message "Master Node started with PID $(cat /var/run/synthron_master_node.pid)."
}

# Function to ensure necessary security measures are in place
setup_security() {
    log_message "Setting up security measures..."

    # Configure firewall (example for UFW)
    if command -v ufw &> /dev/null; then
        ufw allow 30303/tcp
        ufw allow 30303/udp
        log_message "Configured firewall rules for Synthron Master Node."
    fi

    # Enable and configure fail2ban (example configuration)
    if command -v fail2ban-client &> /dev/null; then
        cat <<EOL >/etc/fail2ban/jail.d/synthron.conf
[synthron]
enabled = true
port = 30303
filter = synthron
logpath = /var/log/synthron/*.log
maxretry = 5
EOL
        fail2ban-client reload
        log_message "Configured fail2ban for Synthron Master Node."
    fi
}

# Main script execution
log_message "Initializing Synthron Master Node startup process..."

# Ensure log and data directories exist
ensure_log_directory
ensure_data_directory

# Check for necessary software
check_software

# Check network connectivity
check_network

# Load configuration
load_configuration

# Setup security measures
setup_security

# Start the Master Node
start_master_node

log_message "Synthron Master Node has been started successfully."
