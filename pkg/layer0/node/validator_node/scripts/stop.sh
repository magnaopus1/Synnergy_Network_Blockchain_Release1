#!/bin/bash

# Synthron Blockchain Validator Node Shutdown Script

# Function to print a message with a timestamp
log_message() {
    echo "$(date +'%Y-%m-%d %H:%M:%S') - $1"
}

# Function to check if the required software is installed
check_software() {
    log_message "Checking for required software..."

    required_software=("curl" "jq" "docker" "docker-compose")

    for software in "${required_software[@]}"; do
        if ! command -v $software &> /dev/null; then
            log_message "Error: $software is not installed. Please install it and try again."
            exit 1
        fi
    done

    log_message "All required software is installed."
}

# Function to load environment variables from the config file
load_config() {
    log_message "Loading configuration from config.toml..."
    
    if [ ! -f ./config.toml ]; then
        log_message "Error: config.toml file not found."
        exit 1
    fi

    export VALIDATOR_ADDRESS=$(grep 'validator_address' config.toml | awk -F\" '{print $2}')
    export STAKE_AMOUNT=$(grep 'stake_amount' config.toml | awk -F\" '{print $2}')
    export NETWORK_URL=$(grep 'network_url' config.toml | awk -F\" '{print $2}')

    if [ -z "$VALIDATOR_ADDRESS" ] || [ -z "$STAKE_AMOUNT" ] || [ -z "$NETWORK_URL" ]; then
        log_message "Error: Missing required configuration parameters."
        exit 1
    fi

    log_message "Configuration loaded successfully."
}

# Function to stop Docker containers
stop_docker_containers() {
    log_message "Stopping Docker containers..."
    docker-compose down
    if [ $? -ne 0 ]; then
        log_message "Error: Failed to stop Docker containers."
        exit 1
    fi
    log_message "Docker containers stopped successfully."
}

# Function to safely shut down the validator node
shutdown_validator_node() {
    log_message "Shutting down validator node..."

    # Example shutdown command (replace with actual command)
    docker exec validator_node_container synthron stop --validator-address "$VALIDATOR_ADDRESS"

    if [ $? -ne 0 ]; then
        log_message "Error: Failed to shut down validator node."
        exit 1
    fi

    log_message "Validator node shut down successfully."
}

# Main script execution
log_message "Stopping Synthron Validator Node..."

check_software
load_config
shutdown_validator_node
stop_docker_containers

log_message "Synthron Validator Node stopped successfully."
