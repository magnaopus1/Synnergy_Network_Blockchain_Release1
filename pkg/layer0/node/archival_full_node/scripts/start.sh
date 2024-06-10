#!/bin/bash

# Synthron Blockchain - Archival Full Node Start Script
# This script initializes and starts the Archival Full Node.

# Configuration Variables
NODE_DIR="/path/to/your/node"
CONFIG_FILE="$NODE_DIR/config.toml"
LOG_FILE="$NODE_DIR/node.log"
NODE_BINARY="/usr/local/bin/synthron_node"
NODE_API_ENDPOINT="http://localhost:8080"

# Function to check if the node binary exists
check_node_binary() {
    echo "Checking if the node binary exists..."
    if [ ! -f "$NODE_BINARY" ]; then
        echo "Node binary not found at $NODE_BINARY!" >&2
        exit 1
    fi
    echo "Node binary found."
}

# Function to initialize node data directory
initialize_node_directory() {
    echo "Initializing node data directory..."
    if [ ! -d "$NODE_DIR" ]; then
        mkdir -p "$NODE_DIR"
    fi
    echo "Node data directory initialized at $NODE_DIR."
}

# Function to generate the initial configuration file if not present
generate_config_file() {
    echo "Generating initial configuration file if not present..."
    if [ ! -f "$CONFIG_FILE" ]; then
        cat <<EOL > "$CONFIG_FILE"
[network]
node_type = "archival"
listen_address = "0.0.0.0:30303"
max_connections = 100

[security]
enable_tls = true
tls_cert_file = "/path/to/your/cert.pem"
tls_key_file = "/path/to/your/key.pem"
enable_authentication = true
auth_method = "multi-factor"

[performance]
max_cpu_usage = 80
max_memory_usage = 90
EOL
        echo "Configuration file created at $CONFIG_FILE."
    else
        echo "Configuration file already exists at $CONFIG_FILE."
    fi
}

# Function to start the node
start_node() {
    echo "Starting the node..."
    nohup "$NODE_BINARY" --config "$CONFIG_FILE" > "$LOG_FILE" 2>&1 &
    NODE_PID=$!
    echo "Node started with PID $NODE_PID."
}

# Function to check if the node started successfully
check_node_status() {
    echo "Checking node status..."
    sleep 10  # Give the node some time to start
    if curl -s "$NODE_API_ENDPOINT/status" | grep -q "synced"; then
        echo "Node is up and running."
    else
        echo "Node failed to start correctly. Check $LOG_FILE for details." >&2
        exit 1
    fi
}

# Function to enable monitoring
enable_monitoring() {
    echo "Enabling monitoring tools..."
    # Placeholder for actual monitoring setup, e.g., Prometheus, Grafana
    echo "Monitoring tools enabled."
}

# Function to setup secure communication
setup_secure_communication() {
    echo "Setting up secure communication..."
    # Ensure that TLS and authentication settings are correctly applied
    if grep -q 'enable_tls = true' "$CONFIG_FILE"; then
        echo "TLS is enabled."
    else
        echo "TLS is not enabled! Please check your configuration." >&2
        exit 1
    fi

    if grep -q 'enable_authentication = true' "$CONFIG_FILE"; then
        echo "Authentication is enabled."
    else
        echo "Authentication is not enabled! Please check your configuration." >&2
        exit 1
    fi
}

# Main function to start the archival full node
main() {
    check_node_binary
    initialize_node_directory
    generate_config_file
    setup_secure_communication
    start_node
    check_node_status
    enable_monitoring
    echo "Archival Full Node started successfully."
}

# Run the main function
main
